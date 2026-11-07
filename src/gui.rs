//! The window shown when rdesk.exe is opened with a double click. Hosting and
//! pairing run on Tokio; each remote session opens as its own process, so its
//! window and global keyboard hook cannot disturb this one.

use crate::identity::{short_id, Identity, Trust};
use crate::{host, net, pairing, system};
use anyhow::Result;
use std::cell::{Cell, OnceCell, RefCell};
use std::rc::Rc;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::Controls::{InitCommonControlsEx, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX};
use windows::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow};
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
};
use windows::Win32::UI::WindowsAndMessaging::*;

const CLASS: PCWSTR = w!("rdesk-launcher");
const WM_EVENT: u32 = WM_APP + 1;
const WM_TRAY: u32 = WM_APP + 2;
const TIMER_STATUS: usize = 1;

const ID_HOST_STATUS: i32 = 101;
const ID_HOST_TOGGLE: i32 = 102;
const ID_ADDRESSES: i32 = 103;
const ID_PAIR: i32 = 104;
const ID_CODE: i32 = 105;
const ID_HOST_NOTE: i32 = 106;
const ID_CLIENTS: i32 = 107;
const ID_REVOKE: i32 = 108;
const ID_AUTOSTART: i32 = 109;
const ID_HOSTS: i32 = 110;
const ID_CONNECT: i32 = 111;
const ID_FORGET: i32 = 112;
const ID_QUALITY: i32 = 113;
const ID_NEW_ADDR: i32 = 114;
const ID_NEW_NAME: i32 = 115;
const ID_NEW_CODE: i32 = 116;
const ID_ADD_HOST: i32 = 117;
const ID_CLIENT_STATUS: i32 = 118;
const ID_HOST_PIN: i32 = 119;
const ID_SET_PIN: i32 = 120;
const ID_PIN: i32 = 121;
const ID_CLIPBOARD: i32 = 122;
const ID_COPY_ID: i32 = 123;
const ID_HEAD_LEFT: i32 = 130;
const ID_HEAD_RIGHT: i32 = 131;
const ID_HEAD_NEW: i32 = 132;
const ID_LABEL_FIRST: i32 = 140;
const ID_TRAY_OPEN: i32 = 201;
const ID_TRAY_EXIT: i32 = 202;

const CLIENT_W: i32 = 720;
const CLIENT_H: i32 = 548;
const ES_PASS: u32 = 0x20;
const IDOK_: i32 = 1;

const BS_DEFPUSH: u32 = 1;
const BS_CHECK: u32 = 3 | 0x2000; // Auto checkbox whose text wraps.
const ES_AUTO: u32 = 0x80;
const ES_RO: u32 = 0x800;
const LBS_NOTIFY_: u32 = 1;
const LBS_NOINT: u32 = 0x100;
const CBS_LIST: u32 = 3;
const BN_CLICKED_: usize = 0;
const LBN_DBLCLK_: usize = 2;
const QUALITY: [(&str, u32); 3] =
    [("Экономно: 8 Мбит/с", 8_000), ("Обычно: 20 Мбит/с", 20_000), ("Максимум: 40 Мбит/с", 40_000)];
const QUALITY_DEFAULT: usize = 1;

#[derive(Clone, Copy, PartialEq)]
enum Font {
    Normal,
    Head,
    Code,
}

struct Control {
    id: i32,
    class: PCWSTR,
    text: &'static str,
    style: u32,
    ex: u32,
    font: Font,
    rect: (i32, i32, i32, i32),
}

const STATIC: PCWSTR = w!("STATIC");
const BUTTON: PCWSTR = w!("BUTTON");
const EDIT: PCWSTR = w!("EDIT");
const LISTBOX: PCWSTR = w!("LISTBOX");
const COMBO: PCWSTR = w!("COMBOBOX");
const EX_EDGE: u32 = 0x200;
const TAB: u32 = 0x0001_0000;
const VSCROLL: u32 = 0x0020_0000;

const fn label(id: i32, text: &'static str, rect: (i32, i32, i32, i32)) -> Control {
    Control { id, class: STATIC, text, style: 0, ex: 0, font: Font::Normal, rect }
}
const fn head(id: i32, text: &'static str, rect: (i32, i32, i32, i32)) -> Control {
    Control { id, class: STATIC, text, style: 0, ex: 0, font: Font::Head, rect }
}
const fn button(id: i32, text: &'static str, style: u32, rect: (i32, i32, i32, i32)) -> Control {
    Control { id, class: BUTTON, text, style: style | TAB, ex: 0, font: Font::Normal, rect }
}
const fn edit(id: i32, style: u32, rect: (i32, i32, i32, i32)) -> Control {
    Control { id, class: EDIT, text: "", style: style | ES_AUTO | TAB, ex: EX_EDGE, font: Font::Normal, rect }
}
const fn list(id: i32, rect: (i32, i32, i32, i32)) -> Control {
    Control {
        id,
        class: LISTBOX,
        text: "",
        style: LBS_NOTIFY_ | LBS_NOINT | VSCROLL | TAB,
        ex: EX_EDGE,
        font: Font::Normal,
        rect,
    }
}

/// Layout in 96-DPI units; everything is scaled to the monitor's DPI.
const CONTROLS: [Control; 35] = [
    head(ID_HEAD_LEFT, "Этот компьютер", (20, 14, 320, 26)),
    label(ID_HOST_STATUS, "Подключения выключены", (20, 44, 320, 20)),
    button(ID_HOST_TOGGLE, "Разрешить подключения", 0, (20, 68, 220, 32)),
    label(ID_LABEL_FIRST, "ID этого ПК (сообщите его, чтобы подключаться сюда):", (20, 110, 320, 18)),
    edit(ID_ADDRESSES, ES_RO, (20, 128, 228, 24)),
    button(ID_COPY_ID, "Копировать", 0, (254, 127, 86, 26)),
    label(ID_LABEL_FIRST + 7, "PIN:", (20, 166, 35, 20)),
    edit(ID_HOST_PIN, ES_PASS, (58, 162, 142, 24)),
    button(ID_SET_PIN, "Задать PIN", 0, (210, 160, 130, 28)),
    button(ID_PAIR, "Добавить устройство", 0, (20, 198, 220, 30)),
    Control { id: ID_CODE, class: STATIC, text: "", style: 0, ex: 0, font: Font::Code, rect: (20, 232, 320, 42) },
    label(ID_HOST_NOTE, "", (20, 274, 320, 36)),
    label(ID_LABEL_FIRST + 1, "Устройства с доступом сюда:", (20, 314, 320, 18)),
    list(ID_CLIENTS, (20, 332, 320, 76)),
    button(ID_REVOKE, "Отозвать доступ", 0, (20, 414, 160, 28)),
    button(ID_AUTOSTART, "Запускать при входе в Windows и принимать подключения", BS_CHECK, (20, 448, 320, 38)),
    head(ID_HEAD_RIGHT, "Подключиться к компьютеру", (380, 14, 320, 26)),
    list(ID_HOSTS, (380, 44, 320, 92)),
    button(ID_CONNECT, "Подключиться", BS_DEFPUSH, (380, 142, 160, 32)),
    button(ID_FORGET, "Удалить", 0, (550, 142, 90, 32)),
    label(ID_LABEL_FIRST + 8, "PIN:", (380, 186, 70, 20)),
    edit(ID_PIN, ES_PASS, (455, 182, 245, 24)),
    label(ID_LABEL_FIRST + 2, "Качество:", (380, 216, 70, 20)),
    Control { id: ID_QUALITY, class: COMBO, text: "", style: CBS_LIST | VSCROLL | TAB, ex: 0, font: Font::Normal, rect: (455, 212, 245, 200) },
    button(ID_CLIPBOARD, "Общий буфер обмена с этим компьютером", BS_CHECK, (380, 242, 320, 24)),
    head(ID_HEAD_NEW, "Новый компьютер", (380, 274, 320, 26)),
    label(ID_LABEL_FIRST + 3, "ID:", (380, 308, 70, 20)),
    edit(ID_NEW_ADDR, 0, (455, 304, 245, 24)),
    label(ID_LABEL_FIRST + 4, "Название:", (380, 338, 70, 20)),
    edit(ID_NEW_NAME, 0, (455, 334, 245, 24)),
    label(ID_LABEL_FIRST + 5, "Код:", (380, 368, 70, 20)),
    edit(ID_NEW_CODE, 0, (455, 364, 245, 24)),
    button(ID_ADD_HOST, "Добавить", 0, (455, 396, 120, 28)),
    label(ID_CLIENT_STATUS, "", (380, 432, 320, 56)),
    label(
        ID_LABEL_FIRST + 6,
        "В сеансе: Ctrl+Alt+Shift+F полный экран, +M следующий монитор, +Q выход. Файл можно перетащить в окно сеанса.",
        (20, 496, 680, 40),
    ),
];

enum Event {
    PairCode(String),
    PairDone(Result<String, String>),
    HostAdded(Result<String, String>),
    HostEnded(Option<String>),
    Note(String),
}

#[derive(Clone)]
struct Notifier {
    tx: Sender<Event>,
    hwnd: isize,
}

impl Notifier {
    fn send(&self, event: Event) {
        let _ = self.tx.send(event);
        let _ = unsafe { PostMessageW(HWND(self.hwnd as *mut _), WM_EVENT, WPARAM(0), LPARAM(0)) };
    }
}

struct HostRun {
    stop: Arc<Notify>,
    task: JoinHandle<()>,
}

struct App {
    hwnd: HWND,
    runtime: tokio::runtime::Handle,
    id: Arc<Identity>,
    notifier: Notifier,
    events: Receiver<Event>,
    host: RefCell<Option<HostRun>>,
    pairing: RefCell<Option<JoinHandle<()>>>,
    fonts: RefCell<Vec<(Font, HFONT)>>,
    tray_icon: HICON,
    last_tray_tip: RefCell<String>,
    hosting_shown: Cell<bool>,
}

thread_local! {
    static APP: OnceCell<Rc<App>> = const { OnceCell::new() };
}

fn app() -> Option<Rc<App>> {
    APP.with(|a| a.get().cloned())
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn ctl(hwnd: HWND, id: i32) -> HWND {
    unsafe { GetDlgItem(hwnd, id) }.unwrap_or_default()
}

fn set_text(hwnd: HWND, id: i32, text: &str) {
    let text = wide(text);
    let _ = unsafe { SetWindowTextW(ctl(hwnd, id), PCWSTR(text.as_ptr())) };
}

fn get_text(hwnd: HWND, id: i32) -> String {
    unsafe {
        let control = ctl(hwnd, id);
        let mut buffer = vec![0u16; GetWindowTextLengthW(control) as usize + 1];
        let n = GetWindowTextW(control, &mut buffer) as usize;
        String::from_utf16_lossy(&buffer[..n]).trim().to_string()
    }
}

fn enable(hwnd: HWND, id: i32, on: bool) {
    let _ = unsafe { EnableWindow(ctl(hwnd, id), on) };
}

fn list_selection(hwnd: HWND, id: i32) -> Option<usize> {
    let r = unsafe { SendMessageW(ctl(hwnd, id), LB_GETCURSEL, WPARAM(0), LPARAM(0)) };
    (r.0 >= 0).then_some(r.0 as usize)
}

fn fill_list(hwnd: HWND, id: i32, items: &[String]) {
    unsafe {
        let control = ctl(hwnd, id);
        SendMessageW(control, LB_RESETCONTENT, WPARAM(0), LPARAM(0));
        for item in items {
            let text = wide(item);
            SendMessageW(control, LB_ADDSTRING, WPARAM(0), LPARAM(text.as_ptr() as isize));
        }
    }
}

fn confirm(hwnd: HWND, text: &str) -> bool {
    let text = wide(text);
    unsafe { MessageBoxW(hwnd, PCWSTR(text.as_ptr()), w!("rdesk"), MB_YESNO | MB_ICONQUESTION) == IDYES }
}

/// Which label the host section shows. Kept separate so it can be tested.
fn host_status_text(listening: bool, session: Option<&str>) -> String {
    match (listening, session) {
        (_, Some(peer)) => format!("● Идёт сеанс: {peer}"),
        (true, None) => "● Ожидает подключения".to_string(),
        (false, None) => "Подключения выключены".to_string(),
    }
}

/// Where to go after pressing "Add": checks input before touching the network.
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

pub fn run(runtime: tokio::runtime::Runtime, id: Identity, background: bool) -> Result<()> {
    unsafe {
        // Named per profile, so a second double click reopens the running copy.
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        let name = format!("Local\\rdesk-{}", crate::identity::fingerprint(appdata.as_bytes()));
        let name = wide(&name);
        let mutex = CreateMutexW(None, false, PCWSTR(name.as_ptr()))?;
        if GetLastError() == ERROR_ALREADY_EXISTS {
            // No window means the holder is dying, so this copy takes over.
            if let Ok(existing) = FindWindowW(CLASS, None) {
                let _ = ShowWindow(existing, SW_SHOW);
                let _ = ShowWindow(existing, SW_RESTORE);
                let _ = SetForegroundWindow(existing);
                let _ = CloseHandle(mutex);
                return Ok(());
            }
        }

        let controls = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_STANDARD_CLASSES,
        };
        let _ = InitCommonControlsEx(&controls);

        let instance = GetModuleHandleW(None)?;
        let icon = LoadImageW(instance, PCWSTR(1 as *const u16), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE)
            .map(|h| HICON(h.0))
            .unwrap_or_default();
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: instance.into(),
            lpszClassName: CLASS,
            hIcon: icon,
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            hbrBackground: GetSysColorBrush(COLOR_WINDOW),
            ..Default::default()
        };
        RegisterClassW(&wc);

        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            CLASS,
            w!("rdesk"),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CLIENT_W,
            CLIENT_H,
            None,
            None,
            instance,
            None,
        )?;

        let (tx, events) = channel();
        let notifier = Notifier { tx, hwnd: hwnd.0 as isize };
        let application = Rc::new(App {
            hwnd,
            runtime: runtime.handle().clone(),
            id: Arc::new(id),
            notifier,
            events,
            host: RefCell::new(None),
            pairing: RefCell::new(None),
            fonts: RefCell::new(Vec::new()),
            tray_icon: icon,
            last_tray_tip: RefCell::new(String::new()),
            hosting_shown: Cell::new(false),
        });
        APP.with(|a| a.set(application.clone()).ok());

        create_controls(&application);
        apply_dpi(&application, GetDpiForWindow(hwnd));
        if !background {
            offer_reset_if_tampered(hwnd);
        }
        refresh_pin_controls(hwnd);
        refresh_lists(hwnd);
        set_text(hwnd, ID_ADDRESSES, &application.id.host_id());
        add_tray(&application);
        SendMessageW(
            ctl(hwnd, ID_AUTOSTART),
            BM_SETCHECK,
            WPARAM(system::autostart_enabled() as usize),
            LPARAM(0),
        );
        SetTimer(hwnd, TIMER_STATUS, 500, None);
        refresh_status(&application);

        if background {
            // Start at login: never prompt and stay in the tray.
            start_host(&application, false);
        } else {
            let _ = ShowWindow(hwnd, SW_SHOW);
        }

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
            if !IsDialogMessageW(hwnd, &msg).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        // Release now: a next start must not see this copy as still running.
        let _ = CloseHandle(mutex);
    }
    // Sessions were stopped in quit(). Workers must end before the process does.
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    Ok(())
}

unsafe fn create_controls(app: &App) {
    let instance = GetModuleHandleW(None).unwrap_or_default();
    for c in &CONTROLS {
        let text = wide(c.text);
        let _ = CreateWindowExW(
            WINDOW_EX_STYLE(c.ex),
            c.class,
            PCWSTR(text.as_ptr()),
            WINDOW_STYLE(c.style) | WS_CHILD | WS_VISIBLE,
            0,
            0,
            0,
            0,
            app.hwnd,
            HMENU(c.id as isize as *mut _),
            instance,
            None,
        );
    }
    let combo = ctl(app.hwnd, ID_QUALITY);
    for (name, _) in QUALITY {
        let text = wide(name);
        SendMessageW(combo, CB_ADDSTRING, WPARAM(0), LPARAM(text.as_ptr() as isize));
    }
    SendMessageW(combo, CB_SETCURSEL, WPARAM(QUALITY_DEFAULT), LPARAM(0));
}

unsafe fn make_font(points_px: i32, weight: i32, dpi: u32) -> HFONT {
    CreateFontW(
        -(points_px * dpi as i32 / 96),
        0,
        0,
        0,
        weight,
        0,
        0,
        0,
        DEFAULT_CHARSET.0 as u32,
        OUT_DEFAULT_PRECIS.0 as u32,
        CLIP_DEFAULT_PRECIS.0 as u32,
        CLEARTYPE_QUALITY.0 as u32,
        0,
        w!("Segoe UI"),
    )
}

/// Sizes the window, positions controls and rebuilds fonts for this DPI.
unsafe fn apply_dpi(app: &App, dpi: u32) {
    let scale = |v: i32| v * dpi as i32 / 96;
    let new_fonts = vec![
        (Font::Normal, make_font(14, 400, dpi)),
        (Font::Head, make_font(17, 600, dpi)),
        (Font::Code, make_font(30, 700, dpi)),
    ];
    for c in &CONTROLS {
        let control = ctl(app.hwnd, c.id);
        let (x, y, w, h) = c.rect;
        let _ = SetWindowPos(control, None, scale(x), scale(y), scale(w), scale(h), SWP_NOZORDER | SWP_NOACTIVATE);
        let font = new_fonts.iter().find(|(f, _)| *f == c.font).map(|(_, h)| *h).unwrap_or_default();
        SendMessageW(control, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    }
    for (_, old) in app.fonts.replace(new_fonts) {
        let _ = DeleteObject(old);
    }

    let style = WINDOW_STYLE(GetWindowLongPtrW(app.hwnd, GWL_STYLE) as u32);
    let mut frame = RECT { left: 0, top: 0, right: scale(CLIENT_W), bottom: scale(CLIENT_H) };
    let _ = AdjustWindowRectExForDpi(&mut frame, style, false, WINDOW_EX_STYLE::default(), dpi);
    let _ = SetWindowPos(
        app.hwnd,
        None,
        0,
        0,
        frame.right - frame.left,
        frame.bottom - frame.top,
        SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
    );
}

fn refresh_lists(hwnd: HWND) {
    match Trust::load() {
        Ok(trust) => {
            let clients: Vec<String> = trust.clients.iter().map(|c| c.name.clone()).collect();
            let hosts: Vec<String> =
                trust.hosts.iter().map(|h| format!("{}  (ID {}…)", h.name, short_id(&h.id))).collect();
            fill_list(hwnd, ID_CLIENTS, &clients);
            fill_list(hwnd, ID_HOSTS, &hosts);
        }
        Err(e) => set_text(hwnd, ID_CLIENT_STATUS, &format!("Не удалось прочитать список: {e:#}")),
    }
}

fn copy_id(app: &App) {
    let note = match crate::clipboard::set_remote_text(&app.id.host_id()) {
        Ok(()) => "ID скопирован. Его можно отправить: без кода и PIN он не даёт доступа.".to_string(),
        Err(e) => format!("Не удалось скопировать: {e:#}"),
    };
    set_text(app.hwnd, ID_HOST_NOTE, &note);
}

fn refresh_status(app: &App) {
    let (listening, session) = host::status();
    let status = host_status_text(listening, session.as_deref());
    if get_text(app.hwnd, ID_HOST_STATUS) != status {
        set_text(app.hwnd, ID_HOST_STATUS, &status);
    }
    let hosting = app.host.borrow().is_some();
    if hosting != app.hosting_shown.get() {
        app.hosting_shown.set(hosting);
        set_text(
            app.hwnd,
            ID_HOST_TOGGLE,
            if hosting { "Запретить подключения" } else { "Разрешить подключения" },
        );
    }
    if let Some(note) = host::take_note() {
        set_text(app.hwnd, ID_HOST_NOTE, &note);
    }
    set_tray_tip(app, &format!("rdesk: {status}"));
}

fn tray_data(app: &App) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: app.hwnd,
        uID: 1,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
        uCallbackMessage: WM_TRAY,
        hIcon: app.tray_icon,
        ..Default::default()
    }
}

fn add_tray(app: &App) {
    let data = tray_data(app);
    let _ = unsafe { Shell_NotifyIconW(NIM_ADD, &data) };
}

fn set_tray_tip(app: &App, tip: &str) {
    if *app.last_tray_tip.borrow() == tip {
        return;
    }
    *app.last_tray_tip.borrow_mut() = tip.to_string();
    let mut data = tray_data(app);
    for (slot, unit) in data.szTip.iter_mut().zip(tip.encode_utf16().take(127)) {
        *slot = unit;
    }
    let _ = unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
}

fn show_main(hwnd: HWND) {
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = ShowWindow(hwnd, SW_RESTORE);
        let _ = SetForegroundWindow(hwnd);
    }
}

/// While the list is refused, every device is refused too. Clearing it is the
/// user's decision: it removes all pairings and the PIN, nothing else.
fn offer_reset_if_tampered(hwnd: HWND) {
    if !Trust::is_tampered() {
        return;
    }
    crate::log_event("device list failed its integrity check");
    let question = "Список устройств изменён не этой программой или создан старой версией rdesk. \
        Пока это так, все подключения отклоняются.\n\n\
        Очистить список? Устройства и PIN придётся настроить заново.\n\n\
        Если вы не обновляли программу, проверьте компьютер на вирусы.";
    if confirm(hwnd, question) {
        if let Err(e) = Trust::default().save() {
            set_text(hwnd, ID_HOST_NOTE, &format!("Не удалось очистить список: {e:#}"));
        } else {
            crate::log_event("device list cleared by the user");
        }
    }
}

fn pin_is_set() -> bool {
    Trust::load().is_ok_and(|t| t.pin.is_some())
}

fn refresh_pin_controls(hwnd: HWND) {
    set_text(hwnd, ID_SET_PIN, if pin_is_set() { "Сменить PIN" } else { "Задать PIN" });
    let clipboard = Trust::load().is_ok_and(|t| t.clipboard);
    unsafe {
        SendMessageW(ctl(hwnd, ID_CLIPBOARD), BM_SETCHECK, WPARAM(clipboard as usize), LPARAM(0));
    }
}

fn set_pin(app: &App) {
    let hwnd = app.hwnd;
    let pin = get_text(hwnd, ID_HOST_PIN);
    let record = match crate::pin::PinRecord::new(&pin) {
        Ok(record) => record,
        Err(e) => return set_text(hwnd, ID_HOST_NOTE, &format!("{e:#}.")),
    };
    let saved = Trust::load().and_then(|mut trust| {
        trust.pin = Some(record);
        trust.save()
    });
    match saved {
        Ok(()) => {
            crate::log_event("PIN changed");
            set_text(hwnd, ID_HOST_PIN, "");
            set_text(hwnd, ID_HOST_NOTE, "PIN сохранён. Его будут вводить при подключении к этому ПК.");
            refresh_pin_controls(hwnd);
        }
        Err(e) => set_text(hwnd, ID_HOST_NOTE, &format!("Не удалось сохранить PIN: {e:#}")),
    }
}

fn toggle_clipboard(app: &App) {
    let hwnd = app.hwnd;
    let control = ctl(hwnd, ID_CLIPBOARD);
    let wanted = unsafe { SendMessageW(control, BM_GETCHECK, WPARAM(0), LPARAM(0)) }.0 == 1;
    let saved = Trust::load().and_then(|mut trust| {
        trust.clipboard = wanted;
        trust.save()
    });
    if let Err(e) = saved {
        set_text(hwnd, ID_CLIENT_STATUS, &format!("Не удалось сохранить настройку: {e:#}"));
        unsafe { SendMessageW(control, BM_SETCHECK, WPARAM(!wanted as usize), LPARAM(0)) };
    }
}

fn start_host(app: &App, may_ask: bool) {
    if app.host.borrow().is_some() {
        return;
    }
    let stop = Arc::new(Notify::new());
    let (id, notifier, stop_task) = (app.id.clone(), app.notifier.clone(), stop.clone());
    let owner = app.hwnd.0 as isize;
    if may_ask {
        set_text(app.hwnd, ID_HOST_NOTE, "Windows может запросить разрешение для брандмауэра: подтвердите его.");
    }
    let task = app.runtime.spawn(async move {
        let warning = tokio::task::spawn_blocking(move || system::ensure_firewall(may_ask, owner)).await;
        notifier.send(Event::Note(warning.ok().flatten().unwrap_or_default()));
        let result = host::run(&id, false, stop_task).await;
        notifier.send(Event::HostEnded(result.err().map(|e| format!("{e:#}"))));
    });
    *app.host.borrow_mut() = Some(HostRun { stop, task });
    refresh_status(app);
}

fn toggle_host(app: &App) {
    let stopping = app.host.borrow().as_ref().map(|h| h.stop.clone());
    match stopping {
        Some(stop) => {
            enable(app.hwnd, ID_HOST_TOGGLE, false);
            stop.notify_one();
        }
        None if !pin_is_set() => {
            set_text(app.hwnd, ID_HOST_NOTE, "Сначала задайте PIN: без него подключения отклоняются.");
        }
        None => start_host(app, true),
    }
}

fn toggle_pairing(app: &App) {
    if let Some(task) = app.pairing.borrow_mut().take() {
        task.abort();
        set_text(app.hwnd, ID_CODE, "");
        set_text(app.hwnd, ID_HOST_NOTE, "");
        set_text(app.hwnd, ID_PAIR, "Добавить устройство");
        return;
    }
    let (id, notifier) = (app.id.clone(), app.notifier.clone());
    let owner = app.hwnd.0 as isize;
    set_text(app.hwnd, ID_PAIR, "Отменить");
    set_text(app.hwnd, ID_HOST_NOTE, "Windows может запросить разрешение для брандмауэра: подтвердите его.");
    let task = app.runtime.spawn(async move {
        let _ = tokio::task::spawn_blocking(move || system::ensure_firewall(true, owner)).await;
        let result = async {
            let node = net::host_node(&id.host_key).await?;
            let code = pairing::generate_code()?;
            notifier.send(Event::PairCode(code.clone()));
            pairing::serve(&node, &code).await
        }
        .await;
        notifier.send(Event::PairDone(result.map_err(|e| format!("{e:#}"))));
    });
    *app.pairing.borrow_mut() = Some(task);
}

fn add_host(app: &App) {
    let hwnd = app.hwnd;
    let input = validate_new_host(
        &get_text(hwnd, ID_NEW_ADDR),
        &get_text(hwnd, ID_NEW_NAME),
        &get_text(hwnd, ID_NEW_CODE),
    );
    let (addr, name, code) = match input {
        Ok(input) => input,
        Err(message) => return set_text(hwnd, ID_CLIENT_STATUS, &message),
    };
    enable(hwnd, ID_ADD_HOST, false);
    set_text(hwnd, ID_CLIENT_STATUS, "Подключаюсь к удалённому ПК…");
    let (id, notifier) = (app.id.clone(), app.notifier.clone());
    app.runtime.spawn(async move {
        let result = pairing::pair_with(&id, &addr, &name, &code).await;
        notifier.send(Event::HostAdded(result.map(|_| name).map_err(|e| format!("{e:#}"))));
    });
}

fn connect(app: &App) {
    let hwnd = app.hwnd;
    let Some(index) = list_selection(hwnd, ID_HOSTS) else {
        return set_text(hwnd, ID_CLIENT_STATUS, "Выберите компьютер в списке.");
    };
    let host = match Trust::load().map(|t| t.hosts.get(index).cloned()) {
        Ok(Some(host)) => host,
        _ => return refresh_lists(hwnd),
    };
    let pin = get_text(hwnd, ID_PIN);
    if pin.is_empty() {
        return set_text(hwnd, ID_CLIENT_STATUS, "Введите PIN удалённого ПК.");
    }
    let quality = unsafe { SendMessageW(ctl(hwnd, ID_QUALITY), CB_GETCURSEL, WPARAM(0), LPARAM(0)) }.0;
    let bitrate = QUALITY.get(quality as usize).map_or(QUALITY[QUALITY_DEFAULT].1, |q| q.1);
    let clipboard = unsafe { SendMessageW(ctl(hwnd, ID_CLIPBOARD), BM_GETCHECK, WPARAM(0), LPARAM(0)) }.0 == 1;
    let spawned = std::env::current_exe().and_then(|exe| {
        let bitrate = bitrate.to_string();
        let mut args = vec!["connect", "--dialogs", "--bitrate", &bitrate];
        if !clipboard {
            args.push("--no-clipboard");
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
    set_text(hwnd, ID_PIN, "");
    match spawned {
        Ok(_) => set_text(hwnd, ID_CLIENT_STATUS, &format!("Подключаюсь к «{}»…", host.name)),
        Err(e) => set_text(hwnd, ID_CLIENT_STATUS, &format!("Не удалось запустить сеанс: {e}")),
    }
}

fn forget_host(app: &App) {
    let hwnd = app.hwnd;
    let Some(index) = list_selection(hwnd, ID_HOSTS) else { return };
    let Ok(mut trust) = Trust::load() else { return };
    let Some(host) = trust.hosts.get(index).cloned() else { return };
    if !confirm(hwnd, &format!("Удалить компьютер «{}» из списка?", host.name)) {
        return;
    }
    trust.hosts.remove(index);
    match trust.save() {
        Ok(()) => refresh_lists(hwnd),
        Err(e) => set_text(hwnd, ID_CLIENT_STATUS, &format!("Не удалось сохранить: {e:#}")),
    }
}

fn revoke_client(app: &App) {
    let hwnd = app.hwnd;
    let Some(index) = list_selection(hwnd, ID_CLIENTS) else { return };
    let Ok(mut trust) = Trust::load() else { return };
    let Some(client) = trust.clients.get(index).cloned() else { return };
    if !confirm(hwnd, &format!("Отозвать доступ у устройства «{}»?", client.name)) {
        return;
    }
    trust.clients.remove(index);
    match trust.save() {
        Ok(()) => {
            crate::log_event(&format!("revoked client '{}'", client.name));
            refresh_lists(hwnd);
        }
        Err(e) => set_text(hwnd, ID_HOST_NOTE, &format!("Не удалось сохранить: {e:#}")),
    }
}

fn toggle_autostart(app: &App) {
    let hwnd = app.hwnd;
    let control = ctl(hwnd, ID_AUTOSTART);
    let wanted = unsafe { SendMessageW(control, BM_GETCHECK, WPARAM(0), LPARAM(0)) }.0 == 1;
    if let Err(e) = system::set_autostart(wanted) {
        set_text(hwnd, ID_HOST_NOTE, &format!("Не удалось изменить автозапуск: {e:#}"));
        unsafe { SendMessageW(control, BM_SETCHECK, WPARAM(!wanted as usize), LPARAM(0)) };
    }
}

fn handle_events(app: &App) {
    let hwnd = app.hwnd;
    while let Ok(event) = app.events.try_recv() {
        match event {
            Event::PairCode(code) => {
                set_text(hwnd, ID_CODE, &code);
                set_text(hwnd, ID_HOST_NOTE, "Введите этот код на другом ПК. Действует 2 минуты, 3 попытки.");
            }
            Event::PairDone(result) => {
                *app.pairing.borrow_mut() = None;
                set_text(hwnd, ID_CODE, "");
                set_text(hwnd, ID_PAIR, "Добавить устройство");
                match result {
                    Ok(name) => {
                        set_text(hwnd, ID_HOST_NOTE, &format!("Устройство «{name}» добавлено."));
                        refresh_lists(hwnd);
                    }
                    Err(message) => set_text(hwnd, ID_HOST_NOTE, &message),
                }
            }
            Event::HostAdded(result) => {
                enable(hwnd, ID_ADD_HOST, true);
                match result {
                    Ok(name) => {
                        set_text(hwnd, ID_CLIENT_STATUS, &format!("Компьютер «{name}» добавлен. Можно подключаться."));
                        set_text(hwnd, ID_NEW_ADDR, "");
                        set_text(hwnd, ID_NEW_NAME, "");
                        set_text(hwnd, ID_NEW_CODE, "");
                        refresh_lists(hwnd);
                    }
                    Err(message) => set_text(hwnd, ID_CLIENT_STATUS, &format!("Не удалось: {message}")),
                }
            }
            Event::HostEnded(error) => {
                *app.host.borrow_mut() = None;
                enable(hwnd, ID_HOST_TOGGLE, true);
                if let Some(error) = error {
                    set_text(hwnd, ID_HOST_NOTE, &format!("Не удалось включить подключения: {error}"));
                    show_main(hwnd);
                }
                refresh_status(app);
            }
            Event::Note(text) => set_text(hwnd, ID_HOST_NOTE, &text),
        }
    }
}

fn tray_menu(hwnd: HWND) {
    unsafe {
        let Ok(menu) = CreatePopupMenu() else { return };
        let _ = AppendMenuW(menu, MF_STRING, ID_TRAY_OPEN as usize, w!("Открыть rdesk"));
        let _ = AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT as usize, w!("Выход"));
        let mut point = POINT::default();
        let _ = windows::Win32::UI::WindowsAndMessaging::GetCursorPos(&mut point);
        let _ = SetForegroundWindow(hwnd);
        let _ = TrackPopupMenu(menu, TPM_RIGHTBUTTON, point.x, point.y, 0, hwnd, None);
        let _ = DestroyMenu(menu);
    }
}

fn quit(app: &App) {
    let running = app.host.borrow_mut().take();
    if let Some(run) = running {
        run.stop.notify_one();
        // Session cleanup releases held keys and closes the banner.
        let _ = app.runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(4), run.task).await
        });
    }
    let data = tray_data(app);
    let _ = unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
    let _ = unsafe { DestroyWindow(app.hwnd) };
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let Some(app) = app() else {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    };
    match msg {
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            let code = (wparam.0 >> 16) & 0xFFFF;
            if id == ID_HOSTS && code == LBN_DBLCLK_ {
                connect(&app);
            } else if code == BN_CLICKED_ {
                match id {
                    ID_HOST_TOGGLE => toggle_host(&app),
                    ID_PAIR => toggle_pairing(&app),
                    ID_REVOKE => revoke_client(&app),
                    ID_AUTOSTART => toggle_autostart(&app),
                    ID_CONNECT | IDOK_ => connect(&app),
                    ID_SET_PIN => set_pin(&app),
                    ID_COPY_ID => copy_id(&app),
                    ID_CLIPBOARD => toggle_clipboard(&app),
                    ID_FORGET => forget_host(&app),
                    ID_ADD_HOST => add_host(&app),
                    ID_TRAY_OPEN => show_main(hwnd),
                    ID_TRAY_EXIT => quit(&app),
                    _ => {}
                }
            }
            LRESULT(0)
        }
        WM_EVENT => {
            handle_events(&app);
            LRESULT(0)
        }
        WM_TIMER => {
            refresh_status(&app);
            LRESULT(0)
        }
        WM_TRAY => {
            match (lparam.0 & 0xFFFF) as u32 {
                WM_LBUTTONUP => show_main(hwnd),
                WM_RBUTTONUP => tray_menu(hwnd),
                _ => {}
            }
            LRESULT(0)
        }
        WM_CTLCOLORSTATIC => {
            let dc = HDC(wparam.0 as *mut _);
            SetBkMode(dc, TRANSPARENT);
            let control = HWND(lparam.0 as *mut _);
            if control == ctl(hwnd, ID_CODE) {
                SetTextColor(dc, COLORREF(0x00D2_641E)); // BGR: the icon's blue
            } else if control == ctl(hwnd, ID_HOST_STATUS) && app.hosting_shown.get() {
                SetTextColor(dc, COLORREF(0x0040_8000)); // BGR: green
            }
            LRESULT(GetSysColorBrush(COLOR_WINDOW).0 as isize)
        }
        WM_DPICHANGED => {
            let suggested = &*(lparam.0 as *const RECT);
            let _ = SetWindowPos(
                hwnd,
                None,
                suggested.left,
                suggested.top,
                suggested.right - suggested.left,
                suggested.bottom - suggested.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            apply_dpi(&app, (wparam.0 & 0xFFFF) as u32);
            LRESULT(0)
        }
        WM_CLOSE => {
            // While accepting connections, closing the window keeps it in the tray.
            if app.host.borrow().is_some() {
                let _ = ShowWindow(hwnd, SW_HIDE);
            } else {
                quit(&app);
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_control_id_is_unique() {
        let mut ids: Vec<i32> = CONTROLS.iter().map(|c| c.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), CONTROLS.len());
    }

    #[test]
    fn controls_fit_inside_the_window() {
        for c in &CONTROLS {
            let (x, y, w, h) = c.rect;
            assert!(x >= 0 && x + w <= CLIENT_W, "control {} is too wide", c.id);
            // The combo box height includes its drop-down list.
            if c.id != ID_QUALITY {
                assert!(y >= 0 && y + h <= CLIENT_H, "control {} is too low", c.id);
            }
        }
    }

    #[test]
    fn host_status_prefers_active_session() {
        assert_eq!(host_status_text(false, None), "Подключения выключены");
        assert_eq!(host_status_text(true, None), "● Ожидает подключения");
        assert_eq!(host_status_text(true, Some("ноут")), "● Идёт сеанс: ноут");
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
}
