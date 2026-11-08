//! The window shown when rdesk.exe is opened with a double click. The layout
//! is in ui/app.slint; this file connects it to hosting, pairing and sessions.
//! Each remote session opens as its own process, so its window and global
//! keyboard hook cannot disturb this one.

slint::include_modules!();

use crate::identity::{short_id, Identity, Trust};
use crate::{host, net, pairing, system};
use anyhow::Result;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use std::cell::{OnceCell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
};
use windows::Win32::UI::WindowsAndMessaging::*;

/// Hidden window that owns the tray icon and lets a second copy find this one.
const CLASS: PCWSTR = w!("rdesk-launcher");
const WM_TRAY: u32 = WM_APP + 2;
const WM_SHOW: u32 = WM_APP + 3;
const ID_TRAY_OPEN: usize = 201;
const ID_TRAY_EXIT: usize = 202;
const QUALITY_KBPS: [u32; 3] = [8_000, 20_000, 40_000];

enum Event {
    PairCode(String),
    PairDone(Result<String, String>),
    HostAdded(Result<String, String>),
    HostEnded(Option<String>),
    Note(String),
}

struct HostRun {
    stop: Arc<Notify>,
    task: JoinHandle<()>,
}

struct App {
    ui: AppWindow,
    runtime: tokio::runtime::Handle,
    id: Arc<Identity>,
    host: RefCell<Option<HostRun>>,
    pairing: RefCell<Option<JoinHandle<()>>>,
    tray: HWND,
    icon: HICON,
    tray_tip: RefCell<String>,
}

thread_local! {
    static APP: OnceCell<Rc<App>> = const { OnceCell::new() };
}

fn with_app(f: impl FnOnce(&Rc<App>)) {
    if let Some(app) = APP.with(|a| a.get().cloned()) {
        f(&app);
    }
}

/// Delivers an event from a background task to the window thread.
fn post(event: Event) {
    let _ = slint::invoke_from_event_loop(move || with_app(|app| handle_event(app, event)));
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn confirm(text: &str) -> bool {
    let text = wide(text);
    unsafe { MessageBoxW(None, PCWSTR(text.as_ptr()), w!("rdesk"), MB_YESNO | MB_ICONQUESTION) == IDYES }
}

/// Which label the host section shows. Kept separate so it can be tested.
fn host_status_text(listening: bool, session: Option<&str>) -> String {
    match (listening, session) {
        (_, Some(peer)) => format!("Идёт сеанс: {peer}"),
        (true, None) => "Ожидает подключения".to_string(),
        (false, None) => "Подключения выключены".to_string(),
    }
}

/// Checks the "add a computer" input before touching the network.
fn validate_new_host(id: &str, name: &str, code: &str) -> Result<(String, String, String), String> {
    if id.is_empty() {
        return Err("Укажите ID удалённого ПК.".to_string());
    }
    let Ok(parsed) = net::parse_id(id) else {
        return Err("Это не похоже на ID: скопируйте его целиком, 64 символа.".to_string());
    };
    if code.chars().filter(char::is_ascii_digit).count() != 8 {
        return Err("Код должен состоять из 8 цифр.".to_string());
    }
    let id = parsed.to_string();
    let name = if name.is_empty() { short_id(&id).to_string() } else { name.to_string() };
    Ok((id, name, code.to_string()))
}

fn devices(items: impl Iterator<Item = (String, String)>) -> ModelRc<Device> {
    let rows: Vec<Device> = items
        .map(|(name, id)| Device {
            name: SharedString::from(name),
            detail: SharedString::from(format!("ID {}…", short_id(&id))),
        })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

pub fn run(runtime: tokio::runtime::Runtime, id: Identity, background: bool) -> Result<()> {
    // Named per profile, so a second double click reopens the running copy.
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let name = wide(&format!("Local\\rdesk-{}", crate::identity::fingerprint(appdata.as_bytes())));
    let mutex = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr()))? };
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        // No window means the holder is dying, so this copy takes over.
        if let Ok(existing) = unsafe { FindWindowW(CLASS, None) } {
            let _ = unsafe { PostMessageW(existing, WM_SHOW, WPARAM(0), LPARAM(0)) };
            let _ = unsafe { CloseHandle(mutex) };
            return Ok(());
        }
    }

    let ui = AppWindow::new()?;
    ui.set_theme_index(system::theme_setting() as i32);
    ui.invoke_apply_theme();
    ui.set_my_id(id.host_id().into());

    let (tray, icon) = create_tray_window()?;
    let app = Rc::new(App {
        ui: ui.clone_strong(),
        runtime: runtime.handle().clone(),
        id: Arc::new(id),
        host: RefCell::new(None),
        pairing: RefCell::new(None),
        tray,
        icon,
        tray_tip: RefCell::new(String::new()),
    });
    APP.with(|a| a.set(app.clone()).ok());
    add_tray(&app);
    connect_callbacks(&ui);

    if !background {
        offer_reset_if_tampered();
    }
    refresh_lists(&app);
    refresh_settings(&app);
    refresh_status(&app);

    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::Repeated, Duration::from_millis(500), || with_app(|app| refresh_status(app)));

    ui.window().on_close_requested(|| {
        // While accepting connections, closing the window keeps it in the tray.
        with_app(|app| {
            if app.host.borrow().is_none() {
                quit(app);
            }
        });
        slint::CloseRequestResponse::HideWindow
    });

    if background {
        // Start at login: never prompt and stay in the tray.
        start_host(&app, false);
    } else {
        ui.show()?;
        theme_title_bars_soon();
    }
    slint::run_event_loop_until_quit()?;

    drop(timer);
    let _ = unsafe { CloseHandle(mutex) };
    // Sessions were stopped in quit(). Workers must end before the process does.
    runtime.shutdown_timeout(Duration::from_secs(2));
    Ok(())
}

fn connect_callbacks(ui: &AppWindow) {
    ui.on_toggle_host(|| with_app(toggle_host));
    ui.on_set_pin(|| with_app(set_pin));
    ui.on_copy_id(|| with_app(copy_id));
    ui.on_toggle_pairing(|| with_app(toggle_pairing));
    ui.on_revoke(|index| with_app(|app| revoke_client(app, index)));
    ui.on_autostart_changed(|on| with_app(|app| toggle_autostart(app, on)));
    ui.on_confirm_changed(|on| with_app(|app| toggle_confirm(app, on)));
    ui.on_open_log(|| with_app(open_log));
    ui.on_connect(|| with_app(connect));
    ui.on_forget(|index| with_app(|app| forget_host(app, index)));
    ui.on_clipboard_changed(|on| with_app(|app| toggle_clipboard(app, on)));
    ui.on_audio_changed(|on| {
        if let Err(e) = system::save_ui_setting("audio", serde_json::json!(on)) {
            crate::log_event(&format!("audio setting not saved: {e:#}"));
        }
    });
    ui.on_add_host(|| with_app(add_host));
    ui.on_theme_changed(|index| {
        if let Err(e) = system::save_theme_setting(index.clamp(0, 2) as u8) {
            crate::log_event(&format!("theme not saved: {e:#}"));
        }
        theme_title_bars();
    });
}

fn show_main(app: &App) {
    let _ = app.ui.show();
    theme_title_bars_soon();
}

/// The native window appears only once the event loop runs, and Windows may
/// restyle it on first paint, so the title bar is themed slightly later.
fn theme_title_bars_soon() {
    slint::Timer::single_shot(Duration::from_millis(300), theme_title_bars);
}

/// Windows draws the title bar from the system theme; this makes it follow
/// the theme chosen in rdesk instead. Every window here is on this thread.
fn theme_title_bars() {
    unsafe extern "system" fn apply(hwnd: HWND, _: LPARAM) -> BOOL {
        system::apply_title_theme(hwnd);
        TRUE
    }
    let thread = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };
    let _ = unsafe { EnumThreadWindows(thread, Some(apply), LPARAM(0)) };
}

/// While the list is refused, every device is refused too. Clearing it is the
/// user's decision: it removes all pairings and the PIN, nothing else.
fn offer_reset_if_tampered() {
    if !Trust::is_tampered() {
        return;
    }
    crate::log_event("device list failed its integrity check");
    let question = "Список устройств изменён не этой программой или создан старой версией rdesk. \
        Пока это так, все подключения отклоняются.\n\n\
        Очистить список? Устройства и PIN придётся настроить заново.\n\n\
        Если вы не обновляли программу, проверьте компьютер на вирусы.";
    if confirm(question) {
        match Trust::default().save() {
            Ok(()) => crate::log_event("device list cleared by the user"),
            Err(e) => crate::log_event(&format!("cannot clear device list: {e:#}")),
        }
    }
}

fn refresh_lists(app: &App) {
    match Trust::load() {
        Ok(trust) => {
            app.ui.set_clients(devices(trust.clients.iter().map(|c| (c.name.clone(), c.id.clone()))));
            app.ui.set_hosts(devices(trust.hosts.iter().map(|h| (h.name.clone(), h.id.clone()))));
            if app.ui.get_selected_host() >= trust.hosts.len() as i32 || app.ui.get_selected_host() < 0 {
                app.ui.set_selected_host(if trust.hosts.is_empty() { -1 } else { 0 });
            }
        }
        Err(e) => app.ui.set_client_status(format!("Не удалось прочитать список: {e:#}").into()),
    }
}

fn refresh_settings(app: &App) {
    let trust = Trust::load().unwrap_or_default();
    app.ui.set_pin_set(trust.pin.is_some());
    app.ui.set_clipboard(trust.clipboard);
    app.ui.set_audio(system::ui_flag("audio", true));
    app.ui.set_autostart(system::autostart_enabled());
    app.ui.set_confirm(trust.confirm);
}

fn refresh_status(app: &App) {
    let (listening, session) = host::status();
    let status = host_status_text(listening, session.as_deref());
    let hosting = app.host.borrow().is_some();
    app.ui.set_host_status(status.clone().into());
    app.ui.set_host_active(listening || session.is_some());
    app.ui.set_hosting(hosting);
    app.ui.set_host_toggle_text(if hosting { "Запретить подключения" } else { "Разрешить подключения" }.into());
    if let Some(note) = host::take_note() {
        app.ui.set_host_note(note.into());
    }
    set_tray_tip(app, &format!("rdesk: {status}"));
}

fn note(app: &App, text: &str) {
    app.ui.set_host_note(text.into());
}

fn copy_id(app: &Rc<App>) {
    match crate::clipboard::set_remote_text(&app.id.host_id()) {
        Ok(()) => note(app, "ID скопирован. Его можно отправить: без кода и PIN он не даёт доступа."),
        Err(e) => note(app, &format!("Не удалось скопировать: {e:#}")),
    }
}

fn set_pin(app: &Rc<App>) {
    let pin = app.ui.get_host_pin_input().to_string();
    let record = match crate::pin::PinRecord::new(&pin) {
        Ok(record) => record,
        Err(e) => return note(app, &format!("{e:#}.")),
    };
    let saved = Trust::load().and_then(|mut trust| {
        trust.pin = Some(record);
        trust.save()
    });
    match saved {
        Ok(()) => {
            crate::log_event("PIN changed");
            app.ui.set_host_pin_input(SharedString::new());
            note(app, "PIN сохранён. Его будут вводить при подключении к этому ПК.");
            refresh_settings(app);
        }
        Err(e) => note(app, &format!("Не удалось сохранить PIN: {e:#}")),
    }
}

fn toggle_clipboard(app: &Rc<App>, wanted: bool) {
    let saved = Trust::load().and_then(|mut trust| {
        trust.clipboard = wanted;
        trust.save()
    });
    if let Err(e) = saved {
        app.ui.set_client_status(format!("Не удалось сохранить настройку: {e:#}").into());
        app.ui.set_clipboard(!wanted);
    }
}

fn toggle_confirm(app: &Rc<App>, wanted: bool) {
    let saved = Trust::load().and_then(|mut trust| {
        trust.confirm = wanted;
        trust.save()
    });
    match saved {
        Ok(()) => crate::log_event(if wanted { "confirmation turned on" } else { "confirmation turned off" }),
        Err(e) => {
            note(app, &format!("Не удалось сохранить настройку: {e:#}"));
            app.ui.set_confirm(!wanted);
        }
    }
}

/// Turns a line of rdesk.log into words for the journal, or None for lines
/// that only matter when debugging.
fn describe_log(message: &str) -> Option<String> {
    let quoted = |rest: &str| rest.split('\'').nth(1).unwrap_or("?").to_string();
    let text = if let Some(rest) = message.strip_prefix("session started: ") {
        format!("Подключилось устройство «{}»", quoted(rest))
    } else if let Some(rest) = message.strip_prefix("session ended: ") {
        format!("Сеанс с «{}» завершён", quoted(rest))
    } else if let Some(rest) = message.strip_prefix("wrong PIN from ") {
        format!("Неверный PIN с устройства «{}»", quoted(rest))
    } else if let Some(rest) = message.strip_prefix("refused ") {
        format!("Отклонено подключение «{}»", quoted(rest))
    } else if let Some(rest) = message.strip_prefix("rejected unpaired client ") {
        format!("Отклонено неизвестное устройство {rest}")
    } else if let Some(rest) = message.strip_prefix("session from ") {
        let who = quoted(rest);
        if rest.ends_with("refused at this PC") {
            format!("На этом ПК отказано устройству «{who}»")
        } else if rest.ends_with("view only") {
            format!("На этом ПК разрешён только просмотр для «{who}»")
        } else {
            format!("На этом ПК разрешено подключение «{who}»")
        }
    } else if let Some(rest) = message.strip_prefix("paired client ") {
        format!("Добавлено устройство «{}»", quoted(rest))
    } else if let Some(rest) = message.strip_prefix("revoked client ") {
        format!("Отозван доступ у «{}»", quoted(rest))
    } else if let Some(rest) = message.strip_prefix("connected to ") {
        format!("Вы подключились к «{}»", quoted(rest))
    } else if message == "client session ended" {
        "Ваш сеанс завершён".to_string()
    } else if message == "PIN changed" {
        "PIN изменён".to_string()
    } else if message == "session ended from the banner on this PC" {
        "Сеанс завершён кнопкой «Отключить» на этом ПК".to_string()
    } else if message.starts_with("received ") && message.contains(" files into ") {
        format!("Получены файлы: {}", message.trim_start_matches("received "))
    } else {
        return None;
    };
    Some(text)
}

const LOG_LIMIT: usize = 300;

fn log_entries(log: &str) -> Vec<LogEntry> {
    let mut entries: Vec<LogEntry> = log
        .lines()
        .filter_map(|line| {
            let (secs, message) = line.split_once(' ')?;
            let text = describe_log(message)?;
            Some(LogEntry { time: system::local_time_text(secs.parse().ok()?).into(), text: text.into() })
        })
        .collect();
    entries.reverse();
    entries.truncate(LOG_LIMIT);
    entries
}

fn open_log(app: &Rc<App>) {
    let text = crate::identity::config_dir()
        .and_then(|dir| Ok(std::fs::read_to_string(dir.join("rdesk.log"))?))
        .unwrap_or_default();
    app.ui.set_log_entries(ModelRc::new(VecModel::from(log_entries(&text))));
    app.ui.set_show_log(true);
}

fn toggle_autostart(app: &Rc<App>, wanted: bool) {
    if let Err(e) = system::set_autostart(wanted) {
        note(app, &format!("Не удалось изменить автозапуск: {e:#}"));
        app.ui.set_autostart(!wanted);
    }
}

fn start_host(app: &App, may_ask: bool) {
    if app.host.borrow().is_some() {
        return;
    }
    let stop = Arc::new(Notify::new());
    let (id, stop_task) = (app.id.clone(), stop.clone());
    let owner = app.tray.0 as isize;
    if may_ask {
        note(app, "Windows может запросить разрешение для брандмауэра: подтвердите его.");
    }
    let task = app.runtime.spawn(async move {
        let warning = tokio::task::spawn_blocking(move || system::ensure_firewall(may_ask, owner)).await;
        post(Event::Note(warning.ok().flatten().unwrap_or_default()));
        let result = host::run(&id, false, stop_task).await;
        post(Event::HostEnded(result.err().map(|e| format!("{e:#}"))));
    });
    *app.host.borrow_mut() = Some(HostRun { stop, task });
    refresh_status(app);
}

fn toggle_host(app: &Rc<App>) {
    let stopping = app.host.borrow().as_ref().map(|h| h.stop.clone());
    match stopping {
        Some(stop) => {
            app.ui.set_host_toggle_enabled(false);
            stop.notify_one();
        }
        None if !Trust::load().is_ok_and(|t| t.pin.is_some()) => {
            note(app, "Сначала задайте PIN: без него подключения отклоняются.");
        }
        None => start_host(app, true),
    }
}

fn toggle_pairing(app: &Rc<App>) {
    if let Some(task) = app.pairing.borrow_mut().take() {
        task.abort();
        app.ui.set_code(SharedString::new());
        note(app, "");
        app.ui.set_pair_text("Добавить устройство".into());
        return;
    }
    let id = app.id.clone();
    let owner = app.tray.0 as isize;
    app.ui.set_pair_text("Отменить".into());
    note(app, "Windows может запросить разрешение для брандмауэра: подтвердите его.");
    let task = app.runtime.spawn(async move {
        let _ = tokio::task::spawn_blocking(move || system::ensure_firewall(true, owner)).await;
        let result = async {
            let node = net::host_node(&id.host_key).await?;
            let code = pairing::generate_code()?;
            post(Event::PairCode(code.clone()));
            pairing::serve(&node, &code).await
        }
        .await;
        post(Event::PairDone(result.map_err(|e| format!("{e:#}"))));
    });
    *app.pairing.borrow_mut() = Some(task);
}

fn add_host(app: &Rc<App>) {
    let input = validate_new_host(
        app.ui.get_new_id().trim(),
        app.ui.get_new_name().trim(),
        app.ui.get_new_code().trim(),
    );
    let (host_id, name, code) = match input {
        Ok(input) => input,
        Err(message) => return app.ui.set_client_status(message.into()),
    };
    app.ui.set_adding(true);
    app.ui.set_client_status("Подключаюсь к удалённому ПК…".into());
    let id = app.id.clone();
    app.runtime.spawn(async move {
        let result = pairing::pair_with(&id, &host_id, &name, &code).await;
        post(Event::HostAdded(result.map(|_| name).map_err(|e| format!("{e:#}"))));
    });
}

fn connect(app: &Rc<App>) {
    let index = app.ui.get_selected_host();
    let host = match Trust::load().map(|t| t.hosts.get(index.max(0) as usize).cloned()) {
        Ok(Some(host)) if index >= 0 => host,
        _ => return app.ui.set_client_status("Выберите компьютер в списке.".into()),
    };
    let pin = app.ui.get_pin_input().to_string();
    if pin.is_empty() {
        return app.ui.set_client_status("Введите PIN удалённого ПК.".into());
    }
    let quality = app.ui.get_quality_index().clamp(0, 2) as usize;
    let bitrate = QUALITY_KBPS[quality].to_string();
    let clipboard = app.ui.get_clipboard();
    let audio = app.ui.get_audio();
    let spawned = std::env::current_exe().and_then(|exe| {
        let mut args = vec!["connect", "--dialogs", "--bitrate", &bitrate];
        if !clipboard {
            args.push("--no-clipboard");
        }
        if !audio {
            args.push("--no-audio");
        }
        args.extend(["--", &host.name]);
        let mut child = std::process::Command::new(exe)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        // Through a pipe: other programs can read a process's command line.
        if let Some(mut stdin) = child.stdin.take() {
            std::io::Write::write_all(&mut stdin, format!("{pin}\n").as_bytes())?;
        }
        Ok(child)
    });
    app.ui.set_pin_input(SharedString::new());
    let status = match spawned {
        Ok(_) => format!("Подключаюсь к «{}»…", host.name),
        Err(e) => format!("Не удалось запустить сеанс: {e}"),
    };
    app.ui.set_client_status(status.into());
}

fn forget_host(app: &Rc<App>, index: i32) {
    let Ok(mut trust) = Trust::load() else { return };
    let Some(host) = trust.hosts.get(index.max(0) as usize).cloned() else { return };
    if index < 0 || !confirm(&format!("Удалить компьютер «{}» из списка?", host.name)) {
        return;
    }
    trust.hosts.remove(index as usize);
    match trust.save() {
        Ok(()) => refresh_lists(app),
        Err(e) => app.ui.set_client_status(format!("Не удалось сохранить: {e:#}").into()),
    }
}

fn revoke_client(app: &Rc<App>, index: i32) {
    let Ok(mut trust) = Trust::load() else { return };
    let Some(client) = trust.clients.get(index.max(0) as usize).cloned() else { return };
    if index < 0 || !confirm(&format!("Отозвать доступ у устройства «{}»?", client.name)) {
        return;
    }
    trust.clients.remove(index as usize);
    match trust.save() {
        Ok(()) => {
            crate::log_event(&format!("revoked client '{}'", client.name));
            refresh_lists(app);
        }
        Err(e) => note(app, &format!("Не удалось сохранить: {e:#}")),
    }
}

fn handle_event(app: &Rc<App>, event: Event) {
    match event {
        Event::PairCode(code) => {
            app.ui.set_code(code.into());
            note(app, "Введите этот код на другом ПК. Действует 2 минуты, 3 попытки.");
        }
        Event::PairDone(result) => {
            *app.pairing.borrow_mut() = None;
            app.ui.set_code(SharedString::new());
            app.ui.set_pair_text("Добавить устройство".into());
            match result {
                Ok(name) => {
                    note(app, &format!("Устройство «{name}» добавлено."));
                    refresh_lists(app);
                }
                Err(message) => note(app, &message),
            }
        }
        Event::HostAdded(result) => {
            app.ui.set_adding(false);
            match result {
                Ok(name) => {
                    app.ui.set_client_status(format!("Компьютер «{name}» добавлен. Можно подключаться.").into());
                    app.ui.set_new_id(SharedString::new());
                    app.ui.set_new_name(SharedString::new());
                    app.ui.set_new_code(SharedString::new());
                    refresh_lists(app);
                }
                Err(message) => app.ui.set_client_status(format!("Не удалось: {message}").into()),
            }
        }
        Event::HostEnded(error) => {
            *app.host.borrow_mut() = None;
            app.ui.set_host_toggle_enabled(true);
            if let Some(error) = error {
                note(app, &format!("Не удалось включить подключения: {error}"));
                show_main(app);
            }
            refresh_status(app);
        }
        Event::Note(text) => note(app, &text),
    }
}

fn quit(app: &App) {
    let running = app.host.borrow_mut().take();
    if let Some(run) = running {
        run.stop.notify_one();
        // Session cleanup releases held keys and closes the banner.
        let _ = app.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(4), run.task).await
        });
    }
    let data = tray_data(app.tray, app.icon);
    let _ = unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
    let _ = app.ui.hide();
    let _ = slint::quit_event_loop();
}

fn create_tray_window() -> Result<(HWND, HICON)> {
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let icon = LoadImageW(instance, PCWSTR(1 as *const u16), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE)
            .map(|h| HICON(h.0))
            .unwrap_or_default();
        let wc = WNDCLASSW {
            lpfnWndProc: Some(tray_proc),
            hInstance: instance.into(),
            lpszClassName: CLASS,
            ..Default::default()
        };
        RegisterClassW(&wc);
        // A plain hidden top-level window: message-only windows cannot be
        // found with FindWindow, which the second-copy check relies on.
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            CLASS,
            w!("rdesk"),
            WINDOW_STYLE::default(),
            0,
            0,
            0,
            0,
            None,
            None,
            instance,
            None,
        )?;
        Ok((hwnd, icon))
    }
}

fn tray_data(hwnd: HWND, icon: HICON) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: 1,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
        uCallbackMessage: WM_TRAY,
        hIcon: icon,
        ..Default::default()
    }
}

fn add_tray(app: &App) {
    let data = tray_data(app.tray, app.icon);
    let _ = unsafe { Shell_NotifyIconW(NIM_ADD, &data) };
}

fn set_tray_tip(app: &App, tip: &str) {
    if *app.tray_tip.borrow() == tip {
        return;
    }
    *app.tray_tip.borrow_mut() = tip.to_string();
    let mut data = tray_data(app.tray, app.icon);
    for (slot, unit) in data.szTip.iter_mut().zip(tip.encode_utf16().take(127)) {
        *slot = unit;
    }
    let _ = unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
}

fn tray_menu(hwnd: HWND) {
    unsafe {
        let Ok(menu) = CreatePopupMenu() else { return };
        let _ = AppendMenuW(menu, MF_STRING, ID_TRAY_OPEN, w!("Открыть rdesk"));
        let _ = AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, w!("Выход"));
        let mut point = POINT::default();
        let _ = GetCursorPos(&mut point);
        let _ = SetForegroundWindow(hwnd);
        let _ = TrackPopupMenu(menu, TPM_RIGHTBUTTON, point.x, point.y, 0, hwnd, None);
        let _ = DestroyMenu(menu);
    }
}

/// Runs inside the shared event loop; the work is queued so the interface is
/// never touched from the middle of another window's message.
unsafe extern "system" fn tray_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let later = |f: fn(&Rc<App>)| {
        let _ = slint::invoke_from_event_loop(move || with_app(f));
    };
    match msg {
        WM_TRAY => {
            match (lparam.0 & 0xFFFF) as u32 {
                WM_LBUTTONUP => later(|app| show_main(app)),
                WM_RBUTTONUP => tray_menu(hwnd),
                _ => {}
            }
            LRESULT(0)
        }
        WM_SHOW => {
            later(|app| show_main(app));
            LRESULT(0)
        }
        WM_COMMAND => {
            match wparam.0 & 0xFFFF {
                ID_TRAY_OPEN => later(|app| show_main(app)),
                ID_TRAY_EXIT => later(|app| quit(app)),
                _ => {}
            }
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_status_prefers_active_session() {
        assert_eq!(host_status_text(false, None), "Подключения выключены");
        assert_eq!(host_status_text(true, None), "Ожидает подключения");
        assert_eq!(host_status_text(true, Some("ноут")), "Идёт сеанс: ноут");
    }

    #[test]
    fn new_host_input_is_checked_before_connecting() {
        let id = iroh::SecretKey::from_bytes(&[7; 32]).public().to_string();
        assert!(validate_new_host("", "n", "12345678").is_err());
        assert!(validate_new_host("192.168.1.5", "n", "12345678").is_err());
        assert!(validate_new_host(&id, "n", "123").is_err());
        let (parsed, name, _) = validate_new_host(&format!(" {id} "), "", "1234-5678").unwrap();
        assert_eq!(parsed, id);
        assert_eq!(name, &id[..8]);
        let (_, name, _) = validate_new_host(&id, "Дом", "12345678").unwrap();
        assert_eq!(name, "Дом");
    }

    #[test]
    fn log_lines_become_readable_entries() {
        let log = "100 session started: 'ноут' abcd1234\n\
                   101 encoder: AMD 1920x1080\n\
                   102 wrong PIN from 'ноут', attempts left: 4\n\
                   103 session from 'ноут' allowed at this PC, view only\n\
                   104 session ended: 'ноут'\n";
        let entries = log_entries(log);
        let texts: Vec<String> = entries.iter().map(|e| e.text.to_string()).collect();
        assert_eq!(
            texts,
            [
                "Сеанс с «ноут» завершён",
                "На этом ПК разрешён только просмотр для «ноут»",
                "Неверный PIN с устройства «ноут»",
                "Подключилось устройство «ноут»",
            ]
        );
    }

    #[test]
    fn device_rows_show_short_ids() {
        use slint::Model;
        let model = devices(std::iter::once(("Дом".to_string(), "abcdef0123456789".to_string())));
        let row = model.row_data(0).unwrap();
        assert_eq!(row.name, "Дом");
        assert_eq!(row.detail, "ID abcdef01…");
    }
}
