// an interactive browser for the vault: fuzzy search, details, and copying
// values to the clipboard
//
// moving around never decrypts secrets (which could trigger master password
// reprompts): the list and the details only show what `rbw show` shows, and
// secrets are decrypted when they are copied or explicitly revealed. the one
// exception is the totp code of the selected entry, which is shown live
// unless the entry has master password reprompt enabled.

use std::fmt::Write as _;

use crate::commands::Decryptor;
use crate::term::{Key, Terminal};

const TICK: std::time::Duration = std::time::Duration::from_millis(250);
const STATUS_TIME: std::time::Duration = std::time::Duration::from_secs(4);
// copied values are cleared from the clipboard after this long, or when the
// tui exits, whichever comes first
const CLIPBOARD_TIME: std::time::Duration =
    std::time::Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Login,
    Card,
    Identity,
    Note,
    SshKey,
}

impl Kind {
    const ALL: [Self; 5] = [
        Self::Login,
        Self::Card,
        Self::Identity,
        Self::Note,
        Self::SshKey,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Login => "Login",
            Self::Card => "Card",
            Self::Identity => "Identity",
            Self::Note => "Secure note",
            Self::SshKey => "SSH key",
        }
    }
}

enum Value {
    Plain(String),
    // the cipherstring, decrypted on demand
    Secret(String),
    Totp(String),
}

struct Row {
    label: String,
    value: Value,
}

struct Item {
    id: String,
    name: String,
    user: Option<String>,
    folder: Option<String>,
    kind: Kind,
    reprompt: bool,
    entry_key: Option<String>,
    org_id: Option<String>,
    rows: Vec<Row>,
    notes: Option<String>,
}

impl Item {
    fn row(&self, label: &str) -> Option<usize> {
        self.rows.iter().position(|row| row.label == label)
    }

    // the secret ^P copies
    fn main_secret(&self) -> Option<usize> {
        match self.kind {
            Kind::Login => self.row("password"),
            Kind::Card => self.row("number"),
            Kind::SshKey => self.row("private key"),
            Kind::Identity | Kind::Note => None,
        }
    }

    fn totp(&self) -> Option<usize> {
        self.rows
            .iter()
            .position(|row| matches!(row.value, Value::Totp(_)))
    }

    fn uri(&self) -> Option<&str> {
        self.rows.iter().find_map(|row| match &row.value {
            Value::Plain(uri) if row.label == "uri" => Some(uri.as_str()),
            _ => None,
        })
    }

    // how well the item matches the search terms, if it matches all of them
    fn score(&self, terms: &[String]) -> Option<i64> {
        let mut total = 0;
        for term in terms {
            // the name is what people search for most of the time
            let name = crate::fuzzy::score(term, &self.name).map(|s| s + 10);
            let others = self
                .user
                .iter()
                .chain(&self.folder)
                .map(String::as_str)
                .chain(self.rows.iter().filter_map(|row| match &row.value {
                    Value::Plain(uri) if row.label == "uri" => {
                        Some(uri.as_str())
                    }
                    _ => None,
                }))
                .filter_map(|text| crate::fuzzy::score(term, text))
                .max();
            total += name.max(others)?;
        }
        Some(total)
    }
}

// decrypts everything about an entry except its secrets. failures are shown
// in place of the value, so that one broken entry doesn't make the whole
// vault unusable.
fn decrypt_item(entry: &rbw::db::Entry, decryptor: &dyn Decryptor) -> Item {
    let decrypt = |cipherstring: &str| {
        decryptor
            .decrypt(
                cipherstring,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .unwrap_or_else(|_| "<failed to decrypt>".to_string())
    };
    let row = |label: &str, value: Value| Row {
        label: label.to_string(),
        value,
    };
    let plain = |label: &str, cipherstring: &Option<String>| {
        cipherstring.as_deref().map(|cipherstring| {
            row(label, Value::Plain(decrypt(cipherstring)))
        })
    };
    let secret = |label: &str, cipherstring: &Option<String>| {
        cipherstring.as_ref().map(|cipherstring| {
            row(label, Value::Secret(cipherstring.clone()))
        })
    };

    let mut rows = vec![];
    let mut user = None;
    let kind = match &entry.data {
        rbw::db::EntryData::Login {
            username,
            password,
            totp,
            uris,
        } => {
            user = username.as_deref().map(decrypt);
            rows.extend(
                user.clone().map(|user| row("username", Value::Plain(user))),
            );
            rows.extend(secret("password", password));
            rows.extend(
                totp.as_ref()
                    .map(|totp| row("totp", Value::Totp(totp.clone()))),
            );
            for uri in uris {
                rows.push(row("uri", Value::Plain(decrypt(&uri.uri))));
            }
            Kind::Login
        }
        rbw::db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => {
            rows.extend(plain("cardholder", cardholder_name));
            rows.extend(plain("brand", brand));
            rows.extend(secret("number", number));
            if let (Some(month), Some(year)) = (exp_month, exp_year) {
                let expiration =
                    format!("{}/{}", decrypt(month), decrypt(year));
                rows.push(row("expiration", Value::Plain(expiration)));
            }
            rows.extend(secret("cvv", code));
            Kind::Card
        }
        rbw::db::EntryData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => {
            let name: Vec<String> =
                [title, first_name, middle_name, last_name]
                    .into_iter()
                    .flatten()
                    .map(|s| decrypt(s))
                    .collect();
            if !name.is_empty() {
                rows.push(row("name", Value::Plain(name.join(" "))));
            }
            user = username.as_deref().map(decrypt);
            rows.extend(
                user.clone().map(|user| row("username", Value::Plain(user))),
            );
            rows.extend(plain("email", email));
            rows.extend(plain("phone", phone));
            rows.extend(plain("address", address1));
            rows.extend(plain("address", address2));
            rows.extend(plain("address", address3));
            rows.extend(plain("city", city));
            rows.extend(plain("state", state));
            rows.extend(plain("postcode", postal_code));
            rows.extend(plain("country", country));
            // the agent protects these with the master password reprompt
            rows.extend(secret("ssn", ssn));
            rows.extend(plain("license", license_number));
            rows.extend(secret("passport", passport_number));
            Kind::Identity
        }
        rbw::db::EntryData::SecureNote => Kind::Note,
        rbw::db::EntryData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => {
            rows.extend(plain("public key", public_key));
            rows.extend(plain("fingerprint", fingerprint));
            rows.extend(secret("private key", private_key));
            Kind::SshKey
        }
    };

    for field in &entry.fields {
        let label = field.name.as_deref().map_or_else(String::new, decrypt);
        let value = match (field.ty, &field.value) {
            (Some(rbw::api::FieldType::Hidden), Some(value)) => {
                Value::Secret(value.clone())
            }
            (_, Some(value)) => Value::Plain(decrypt(value)),
            (Some(rbw::api::FieldType::Linked), None) => {
                Value::Plain("(linked)".to_string())
            }
            (_, None) => Value::Plain(String::new()),
        };
        rows.push(Row { label, value });
    }

    Item {
        id: entry.id.clone(),
        name: decrypt(&entry.name),
        user,
        // folders are always encrypted with the user's own key
        folder: entry.folder.as_deref().map(|folder| {
            decryptor
                .decrypt(folder, None, None)
                .unwrap_or_else(|_| "<failed to decrypt>".to_string())
        }),
        kind,
        reprompt: entry.master_password_reprompt(),
        entry_key: entry.key.clone(),
        org_id: entry.org_id.clone(),
        rows,
        notes: entry.notes.as_deref().map(decrypt),
    }
}

fn load_items() -> anyhow::Result<Vec<Item>> {
    let db = crate::commands::load_db()?;
    let mut items =
        crate::commands::batch_decrypt(&db.entries, |entry, decryptor| {
            Ok(decrypt_item(entry, decryptor))
        })?;
    items.sort_by_cached_key(|item| item.name.to_lowercase());
    Ok(items)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Filter {
    All,
    Kind(Kind),
    Folder(Option<String>),
}

impl Filter {
    fn matches(&self, item: &Item) -> bool {
        match self {
            Self::All => true,
            Self::Kind(kind) => item.kind == *kind,
            Self::Folder(folder) => item.folder == *folder,
        }
    }
}

struct SideRow {
    label: String,
    // None for section headings
    filter: Option<Filter>,
    count: usize,
}

fn sidebar_rows(items: &[Item]) -> Vec<SideRow> {
    let count = |filter: &Filter| {
        items.iter().filter(|item| filter.matches(item)).count()
    };
    let mut rows = vec![SideRow {
        label: "All items".to_string(),
        filter: Some(Filter::All),
        count: items.len(),
    }];
    rows.push(SideRow {
        label: "Types".to_string(),
        filter: None,
        count: 0,
    });
    for kind in Kind::ALL {
        let filter = Filter::Kind(kind);
        let count = count(&filter);
        if count > 0 {
            rows.push(SideRow {
                label: kind.name().to_string(),
                filter: Some(filter),
                count,
            });
        }
    }
    let mut folders: Vec<&str> = items
        .iter()
        .filter_map(|item| item.folder.as_deref())
        .collect();
    folders.sort_unstable_by_key(|folder| folder.to_lowercase());
    folders.dedup();
    if !folders.is_empty() {
        rows.push(SideRow {
            label: "Folders".to_string(),
            filter: None,
            count: 0,
        });
        for folder in folders {
            let filter = Filter::Folder(Some(folder.to_string()));
            rows.push(SideRow {
                label: folder.to_string(),
                count: count(&filter),
                filter: Some(filter),
            });
        }
        let filter = Filter::Folder(None);
        rows.push(SideRow {
            label: "No folder".to_string(),
            count: count(&filter),
            filter: Some(filter),
        });
    }
    rows
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Sidebar,
    List,
    Details,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    CopyMain,
    CopyUser,
    CopyTotp,
    Reveal,
    Open,
    Fields,
    Sync,
    Lock,
}

enum Popup {
    Actions(usize),
    Help,
}

enum Totp {
    // decrypted for the live code
    Secret(String),
    // not shown live, because of reprompt or a locked agent
    Hidden,
}

struct App {
    items: Vec<Item>,
    query: String,
    filter: Filter,
    // indices into items, in display order
    visible: Vec<usize>,
    selected: usize,
    list_offset: usize,
    focus: Focus,
    sidebar: Vec<SideRow>,
    side_selected: usize,
    side_offset: usize,
    detail_selected: usize,
    detail_offset: usize,
    // the decrypted secrets of the selected entry, by row, once revealed
    revealed: Option<(String, Vec<Option<String>>)>,
    totp: Option<(String, Totp)>,
    popup: Option<Popup>,
    status: Option<(String, bool, std::time::Instant)>,
    // the hash of the last copied value, and when it was copied
    copied: Option<([u8; 32], std::time::Instant)>,
    quit: bool,
    screen: Screen,
}

impl App {
    fn new(items: Vec<Item>) -> Self {
        let mut app = Self {
            sidebar: sidebar_rows(&items),
            items,
            query: String::new(),
            filter: Filter::All,
            visible: vec![],
            selected: 0,
            list_offset: 0,
            focus: Focus::List,
            side_selected: 0,
            side_offset: 0,
            detail_selected: 0,
            detail_offset: 0,
            revealed: None,
            totp: None,
            popup: None,
            status: None,
            copied: None,
            quit: false,
            screen: Screen::default(),
        };
        app.refilter();
        app
    }

    fn run(&mut self, term: &mut Terminal) -> anyhow::Result<()> {
        while !self.quit {
            if self
                .copied
                .is_some_and(|(_, at)| at.elapsed() >= CLIPBOARD_TIME)
            {
                if let Err(e) = self.clear_clipboard() {
                    self.set_status(format!("{e:#}"), true);
                }
            }
            self.update_totp();
            self.draw()?;
            for key in term.read_keys(TICK)? {
                self.handle_key(term, key);
                if self.quit {
                    break;
                }
            }
        }
        Ok(())
    }

    fn current(&self) -> Option<&Item> {
        self.visible.get(self.selected).map(|&i| &self.items[i])
    }

    fn refilter(&mut self) {
        let selected_id = self.current().map(|item| item.id.clone());
        let terms: Vec<String> = self
            .query
            .split_whitespace()
            .map(str::to_lowercase)
            .collect();
        let mut scored: Vec<(i64, usize)> = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| self.filter.matches(item))
            .filter_map(|(i, item)| item.score(&terms).map(|s| (s, i)))
            .collect();
        // items are sorted by name already, and the sort is stable
        scored.sort_by_key(|&(score, _)| std::cmp::Reverse(score));
        self.visible = scored.into_iter().map(|(_, i)| i).collect();
        // when searching, the best match is the interesting one, otherwise
        // keep the selection where it was
        self.selected = if terms.is_empty() {
            selected_id
                .and_then(|id| {
                    self.visible.iter().position(|&i| self.items[i].id == id)
                })
                .unwrap_or(0)
        } else {
            0
        };
        self.selection_changed();
    }

    fn selection_changed(&mut self) {
        let id = self.current().map(|item| item.id.clone());
        if self.revealed.as_ref().map(|(i, _)| i) != id.as_ref() {
            self.revealed = None;
        }
        if self.totp.as_ref().map(|(i, _)| i) != id.as_ref() {
            self.totp = None;
            self.detail_selected = 0;
            self.detail_offset = 0;
        }
    }

    fn set_status(&mut self, message: impl Into<String>, error: bool) {
        self.status =
            Some((message.into(), error, std::time::Instant::now()));
    }

    // decrypts the totp secret of the selected entry for the live code, if
    // that can be done without asking for anything
    fn update_totp(&mut self) {
        let Some(item) = self.current() else {
            return;
        };
        if self.totp.as_ref().is_some_and(|(id, _)| *id == item.id) {
            return;
        }
        let Some(row) = item.totp() else {
            return;
        };
        let Value::Totp(cipherstring) = &item.rows[row].value else {
            return;
        };
        let totp = if item.reprompt || crate::actions::unlocked().is_err() {
            Totp::Hidden
        } else {
            crate::actions::decrypt(
                cipherstring,
                item.entry_key.as_deref(),
                item.org_id.as_deref(),
            )
            .map_or(Totp::Hidden, Totp::Secret)
        };
        self.totp = Some((item.id.clone(), totp));
    }

    // runs a request to the agent which might have to ask for the master
    // password, with the terminal handed back for pinentry if necessary
    fn agent<T>(
        &mut self,
        term: &Terminal,
        reprompt: bool,
        f: impl FnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        if !reprompt && crate::actions::unlocked().is_ok() {
            return f();
        }
        let res = term.suspend(|| {
            crate::actions::unlock()?;
            f()
        })?;
        self.screen.invalidate();
        res
    }

    // the plaintext of a row of the selected entry, decrypting it if needed
    fn row_value(
        &mut self,
        term: &Terminal,
        row: usize,
    ) -> anyhow::Result<String> {
        let Some(item) = self.current() else {
            anyhow::bail!("no entry selected");
        };
        if let Some(Some(plaintext)) = self
            .revealed
            .as_ref()
            .and_then(|(_, revealed)| revealed.get(row))
        {
            return Ok(plaintext.clone());
        }
        let (reprompt, entry_key, org_id) =
            (item.reprompt, item.entry_key.clone(), item.org_id.clone());
        let (cipherstring, totp) = match &item.rows[row].value {
            Value::Plain(value) => return Ok(value.clone()),
            Value::Secret(cipherstring) => (cipherstring.clone(), false),
            Value::Totp(cipherstring) => (cipherstring.clone(), true),
        };
        let plaintext = self.agent(term, reprompt, || {
            crate::actions::decrypt(
                &cipherstring,
                entry_key.as_deref(),
                org_id.as_deref(),
            )
        })?;
        if totp {
            Ok(crate::commands::totp_now(&plaintext)?.0)
        } else {
            Ok(plaintext)
        }
    }

    fn copy_row(&mut self, term: &Terminal, row: Option<usize>) {
        let Some(row) = row else {
            self.set_status("the entry has no such value", true);
            return;
        };
        let label = self
            .current()
            .map(|item| item.rows[row].label.clone())
            .unwrap_or_default();
        let res = self.row_value(term, row).and_then(|value| {
            crate::clipboard::store(&value, crate::clipboard::Mode::On)?;
            Ok(crate::clipboard::hash(&value))
        });
        match res {
            Ok(hash) => {
                self.copied = Some((hash, std::time::Instant::now()));
                self.set_status(
                    format!(
                        "copied {label}, clearing the clipboard in {}s",
                        CLIPBOARD_TIME.as_secs()
                    ),
                    false,
                );
            }
            Err(e) => self.set_status(format!("{e:#}"), true),
        }
    }

    // clears the clipboard if it still holds the last copied value
    fn clear_clipboard(&mut self) -> anyhow::Result<()> {
        let Some((hash, _)) = self.copied.take() else {
            return Ok(());
        };
        if crate::clipboard::clear_if_unchanged(&hash)? {
            self.set_status("cleared the clipboard", false);
        }
        Ok(())
    }

    fn toggle_reveal(&mut self, term: &Terminal) {
        if self.revealed.is_some() {
            self.revealed = None;
            return;
        }
        let Some(item) = self.current() else {
            return;
        };
        let secrets: Vec<(usize, rbw::protocol::DecryptItem)> = item
            .rows
            .iter()
            .enumerate()
            .filter_map(|(i, row)| match &row.value {
                Value::Secret(cipherstring) => Some((
                    i,
                    rbw::protocol::DecryptItem {
                        cipherstring: cipherstring.clone(),
                        entry_key: item.entry_key.clone(),
                        org_id: item.org_id.clone(),
                    },
                )),
                _ => None,
            })
            .collect();
        if secrets.is_empty() {
            self.set_status("the entry has no secrets", false);
            return;
        }
        let (id, reprompt, len) =
            (item.id.clone(), item.reprompt, item.rows.len());
        let (rows, requests): (Vec<usize>, Vec<_>) =
            secrets.into_iter().unzip();
        // one request, so that reprompt asks only once
        match self
            .agent(term, reprompt, || crate::actions::decrypt_many(requests))
        {
            Ok(results) => {
                let mut revealed = vec![None; len];
                for (row, result) in rows.into_iter().zip(results) {
                    revealed[row] = Some(result.unwrap_or_else(|e| {
                        format!("<failed to decrypt: {e}>")
                    }));
                }
                self.revealed = Some((id, revealed));
            }
            Err(e) => self.set_status(format!("{e:#}"), true),
        }
    }

    fn open(&mut self) {
        let Some(uri) =
            self.current().and_then(Item::uri).map(str::to_string)
        else {
            self.set_status("the entry has no web address", true);
            return;
        };
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        let res = std::process::Command::new(opener)
            .arg(&uri)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match res {
            Ok(status) if status.success() => {
                self.set_status(format!("opened {uri}"), false);
            }
            Ok(status) => {
                self.set_status(format!("{opener} failed: {status}"), true);
            }
            Err(e) => self.set_status(format!("{opener}: {e}"), true),
        }
    }

    fn sync(&mut self, term: &Terminal) -> anyhow::Result<()> {
        self.set_status("syncing...", false);
        self.draw()?;
        // syncing works while the agent is locked, but decrypting the new
        // entries doesn't, so unlock it first if necessary
        let res = self.agent(term, false, || {
            crate::actions::sync()?;
            load_items()
        });
        match res {
            Ok(items) => {
                self.sidebar = sidebar_rows(&items);
                self.side_selected = self
                    .sidebar
                    .iter()
                    .position(|row| row.filter.as_ref() == Some(&self.filter))
                    .unwrap_or(0);
                if self.side_selected == 0 {
                    self.filter = Filter::All;
                }
                self.items = items;
                self.revealed = None;
                self.totp = None;
                self.refilter();
                self.set_status("synced", false);
            }
            Err(e) => self.set_status(format!("{e:#}"), true),
        }
        Ok(())
    }

    fn actions(&self) -> Vec<(Action, String, &'static str)> {
        let Some(item) = self.current() else {
            return vec![(Action::Sync, "sync".to_string(), "^S")];
        };
        let mut actions = vec![];
        if let Some(row) = item.main_secret() {
            actions.push((
                Action::CopyMain,
                format!("copy {}", item.rows[row].label),
                "^P",
            ));
        }
        if item.row("username").is_some() {
            actions.push((
                Action::CopyUser,
                "copy username".to_string(),
                "^U",
            ));
        }
        if item.totp().is_some() {
            actions.push((
                Action::CopyTotp,
                "copy totp code".to_string(),
                "^T",
            ));
        }
        if item.uri().is_some() {
            actions.push((
                Action::Open,
                "open the web address".to_string(),
                "^O",
            ));
        }
        if item
            .rows
            .iter()
            .any(|row| matches!(row.value, Value::Secret(_)))
        {
            let label = if self.revealed.is_some() {
                "hide the secrets"
            } else {
                "show the secrets"
            };
            actions.push((Action::Reveal, label.to_string(), "^R"));
        }
        if !item.rows.is_empty() {
            actions.push((
                Action::Fields,
                "copy another field".to_string(),
                "Tab",
            ));
        }
        actions.push((Action::Sync, "sync".to_string(), "^S"));
        actions.push((Action::Lock, "lock and quit".to_string(), "^L"));
        actions
    }

    fn act(&mut self, term: &Terminal, action: Action) {
        match action {
            Action::CopyMain => {
                let row = self.current().and_then(Item::main_secret);
                self.copy_row(term, row);
            }
            Action::CopyUser => {
                let row =
                    self.current().and_then(|item| item.row("username"));
                self.copy_row(term, row);
            }
            Action::CopyTotp => {
                let row = self.current().and_then(Item::totp);
                self.copy_row(term, row);
            }
            Action::Reveal => self.toggle_reveal(term),
            Action::Open => self.open(),
            Action::Fields => {
                if self.current().is_some_and(|item| !item.rows.is_empty()) {
                    self.focus = Focus::Details;
                }
            }
            Action::Sync => {
                if let Err(e) = self.sync(term) {
                    self.set_status(format!("{e:#}"), true);
                }
            }
            Action::Lock => match crate::actions::lock() {
                Ok(()) => self.quit = true,
                Err(e) => self.set_status(format!("{e:#}"), true),
            },
        }
    }

    fn handle_key(&mut self, term: &Terminal, key: Key) {
        match self.popup {
            Some(Popup::Help) => {
                self.popup = None;
                return;
            }
            Some(Popup::Actions(selected)) => {
                let actions = self.actions();
                match key {
                    Key::Up | Key::Ctrl('k') | Key::BackTab => {
                        self.popup =
                            Some(Popup::Actions(selected.saturating_sub(1)));
                    }
                    Key::Down | Key::Ctrl('j') | Key::Tab => {
                        self.popup = Some(Popup::Actions(
                            (selected + 1).min(actions.len() - 1),
                        ));
                    }
                    Key::Enter => {
                        self.popup = None;
                        self.act(term, actions[selected].0);
                    }
                    Key::Esc | Key::Ctrl('c' | 'q') | Key::Left => {
                        self.popup = None;
                    }
                    _ => {
                        // the shortcuts work in the menu as well
                        self.popup = None;
                        self.handle_key(term, key);
                    }
                }
                return;
            }
            None => {}
        }

        match key {
            Key::Ctrl('c' | 'q') => self.quit = true,
            Key::Esc => {
                if self.focus != Focus::List {
                    self.focus = Focus::List;
                } else if self.query.is_empty() {
                    self.quit = true;
                } else {
                    self.query.clear();
                    self.refilter();
                }
            }
            Key::Ctrl('p') => self.act(term, Action::CopyMain),
            Key::Ctrl('u') => self.act(term, Action::CopyUser),
            Key::Ctrl('t') => self.act(term, Action::CopyTotp),
            Key::Ctrl('r') => self.act(term, Action::Reveal),
            Key::Ctrl('o') => self.act(term, Action::Open),
            Key::Ctrl('s') => self.act(term, Action::Sync),
            Key::Ctrl('l') => self.act(term, Action::Lock),
            Key::F(1) => self.popup = Some(Popup::Help),
            Key::Char('?') if self.query.is_empty() => {
                self.popup = Some(Popup::Help);
            }
            Key::Up | Key::Ctrl('k') => self.move_by(-1),
            Key::Down | Key::Ctrl('j') => self.move_by(1),
            Key::PageUp => self.move_by(-self.page()),
            Key::PageDown => self.move_by(self.page()),
            Key::Home => self.move_by(isize::MIN / 2),
            Key::End => self.move_by(isize::MAX / 2),
            Key::Tab => {
                self.focus = match self.focus {
                    Focus::List
                        if self
                            .current()
                            .is_some_and(|i| !i.rows.is_empty()) =>
                    {
                        Focus::Details
                    }
                    _ => Focus::List,
                };
            }
            Key::BackTab | Key::Left => {
                self.focus = match self.focus {
                    Focus::List if self.screen.sidebar_shown => {
                        Focus::Sidebar
                    }
                    Focus::Sidebar if key == Key::BackTab => Focus::List,
                    Focus::Sidebar => Focus::Sidebar,
                    _ => Focus::List,
                };
            }
            Key::Right => {
                self.focus = match self.focus {
                    Focus::List
                        if self
                            .current()
                            .is_some_and(|i| !i.rows.is_empty()) =>
                    {
                        Focus::Details
                    }
                    Focus::Details => Focus::Details,
                    _ => Focus::List,
                };
            }
            Key::Enter => match self.focus {
                Focus::List => {
                    if self.current().is_some() {
                        self.popup = Some(Popup::Actions(0));
                    }
                }
                Focus::Details => {
                    let row = Some(self.detail_selected);
                    self.copy_row(term, row);
                }
                Focus::Sidebar => self.focus = Focus::List,
            },
            Key::Backspace => {
                if self.query.pop().is_some() {
                    self.focus = Focus::List;
                    self.refilter();
                }
            }
            Key::Ctrl('w') | Key::Alt('\x7f') => {
                let trimmed = self.query.trim_end();
                let keep =
                    trimmed.rfind(char::is_whitespace).map_or(0, |i| i + 1);
                self.query.truncate(keep);
                self.focus = Focus::List;
                self.refilter();
            }
            Key::Char(c) => {
                self.query.push(c);
                self.focus = Focus::List;
                self.refilter();
            }
            _ => {}
        }
    }

    fn page(&self) -> isize {
        isize::try_from(self.screen.pane_height.saturating_sub(1).max(1))
            .unwrap_or(1)
    }

    fn move_by(&mut self, delta: isize) {
        let step = |current: usize, len: usize| {
            current
                .saturating_add_signed(delta)
                .min(len.saturating_sub(1))
        };
        match self.focus {
            Focus::List => {
                self.selected = step(self.selected, self.visible.len());
                self.selection_changed();
            }
            Focus::Details => {
                let len = self.current().map_or(0, |item| item.rows.len());
                self.detail_selected = step(self.detail_selected, len);
            }
            Focus::Sidebar => {
                // skip the section headings
                let mut selected =
                    step(self.side_selected, self.sidebar.len());
                while self.sidebar[selected].filter.is_none() {
                    if delta < 0 && selected > 0 {
                        selected -= 1;
                    } else if selected + 1 < self.sidebar.len() {
                        selected += 1;
                    } else {
                        selected = self.side_selected;
                        break;
                    }
                }
                self.side_selected = selected;
                if let Some(filter) = self.sidebar[selected].filter.clone() {
                    self.filter = filter;
                    self.refilter();
                }
            }
        }
    }

    fn draw(&mut self) -> anyhow::Result<()> {
        if self
            .status
            .as_ref()
            .is_some_and(|(_, _, at)| at.elapsed() > STATUS_TIME)
        {
            self.status = None;
        }
        let (width, height) = Terminal::size();
        let mut frame = Frame::new(width, height);
        self.render(&mut frame);
        self.screen.show(&frame)?;
        Ok(())
    }

    fn render(&mut self, frame: &mut Frame) {
        let (width, height) = (frame.width, frame.height);

        // search line
        frame.put(0, 0, "❯ ", ACCENT, width);
        let x = frame.put(
            2,
            0,
            &crate::term::sanitize(&self.query),
            PLAIN,
            width,
        );
        frame.put(x, 0, " ", REVERSE, width);
        let counts = format!("{}/{}", self.visible.len(), self.items.len());
        let counts_x = width.saturating_sub(crate::term::width(&counts) + 1);
        frame.put(counts_x, 0, &counts, DIM, width);

        if height < 5 || width < 20 {
            return;
        }
        let pane_top = 1;
        let pane_height = height - 2;
        self.screen.pane_height = pane_height.saturating_sub(2);

        let sidebar_width = if width >= 100 { 24 } else { 0 };
        self.screen.sidebar_shown = sidebar_width > 0;
        if !self.screen.sidebar_shown && self.focus == Focus::Sidebar {
            self.focus = Focus::List;
        }
        let rest = width - sidebar_width;
        let (list_width, details_width) = if rest >= 60 {
            let list = rest * 9 / 20;
            (list, rest - list)
        } else {
            (rest, 0)
        };
        if details_width == 0 && self.focus == Focus::Details {
            self.focus = Focus::List;
        }

        if sidebar_width > 0 {
            self.render_sidebar(
                frame,
                Rect::new(0, pane_top, sidebar_width, pane_height),
            );
        }
        self.render_list(
            frame,
            Rect::new(sidebar_width, pane_top, list_width, pane_height),
        );
        if details_width > 0 {
            self.render_details(
                frame,
                Rect::new(
                    sidebar_width + list_width,
                    pane_top,
                    details_width,
                    pane_height,
                ),
            );
        }

        self.render_bottom(frame, height - 1);

        match self.popup {
            Some(Popup::Actions(selected)) => {
                self.render_actions(frame, selected);
            }
            Some(Popup::Help) => render_help(frame),
            None => {}
        }
    }

    fn render_sidebar(&mut self, frame: &mut Frame, rect: Rect) {
        let inner = frame.border(rect, "Vault", self.focus == Focus::Sidebar);
        self.side_offset = scroll(
            self.side_offset,
            self.side_selected,
            inner.height,
            self.sidebar.len(),
        );
        for (y, row) in self
            .sidebar
            .iter()
            .enumerate()
            .skip(self.side_offset)
            .take(inner.height)
            .map(|(i, row)| (inner.y + i - self.side_offset, row))
        {
            let Some(filter) = &row.filter else {
                frame.put(inner.x, y, &row.label, HEADING, inner.right());
                continue;
            };
            let style = if *filter == self.filter {
                if self.focus == Focus::Sidebar {
                    SELECTED
                } else {
                    ACCENT_BOLD
                }
            } else {
                PLAIN
            };
            if *filter == self.filter {
                frame.fill(inner.x, y, inner.width, style);
            }
            let label = crate::term::sanitize(&row.label);
            frame.put(inner.x + 1, y, &label, style, inner.right() - 5);
            let count = row.count.to_string();
            let count_x = inner.right().saturating_sub(count.len());
            frame.put(count_x, y, &count, style.dimmed(), inner.right());
        }
    }

    fn render_list(&mut self, frame: &mut Frame, rect: Rect) {
        let title = self
            .sidebar
            .get(self.side_selected)
            .map_or_else(|| "All items".to_string(), |row| row.label.clone());
        let inner = frame.border(
            rect,
            &crate::term::sanitize(&title),
            self.focus == Focus::List,
        );
        self.list_offset = scroll(
            self.list_offset,
            self.selected,
            inner.height,
            self.visible.len(),
        );
        if self.visible.is_empty() {
            let message = if self.items.is_empty() {
                "the vault is empty"
            } else {
                "no matching entries"
            };
            frame.put(inner.x + 1, inner.y, message, DIM, inner.right());
        }
        for (pos, &i) in self
            .visible
            .iter()
            .enumerate()
            .skip(self.list_offset)
            .take(inner.height)
        {
            let item = &self.items[i];
            let y = inner.y + pos - self.list_offset;
            let selected = pos == self.selected;
            let (style, dim, folder_style) =
                if selected && self.focus == Focus::List {
                    (SELECTED, SELECTED, SELECTED)
                } else if selected {
                    (BOLD, DIM, FOLDER)
                } else {
                    (PLAIN, DIM, FOLDER)
                };
            if selected {
                frame.fill(inner.x, y, inner.width, style);
                frame.put(inner.x, y, "▌", ACCENT, inner.right());
            }
            let folder = item.folder.as_deref().map(crate::term::sanitize);
            let folder_width = folder.as_deref().map_or(0, |folder| {
                crate::term::width(folder).min(inner.width / 3)
            });
            let text_right = inner.right() - folder_width - 1;
            let x = frame.put(
                inner.x + 1,
                y,
                &crate::term::sanitize(&item.name),
                style,
                text_right,
            );
            if let Some(user) = &item.user {
                frame.put(
                    x + 2,
                    y,
                    &crate::term::sanitize(user),
                    dim,
                    text_right,
                );
            }
            if let Some(folder) = folder {
                let folder = crate::term::truncate(&folder, folder_width);
                frame.put(
                    inner.right() - crate::term::width(folder),
                    y,
                    folder,
                    folder_style,
                    inner.right(),
                );
            }
        }
    }

    fn render_details(&mut self, frame: &mut Frame, rect: Rect) {
        let Some(&index) = self.visible.get(self.selected) else {
            frame.border(rect, "", false);
            return;
        };
        let item = &self.items[index];
        let inner = frame.border(
            rect,
            &crate::term::sanitize(&item.name),
            self.focus == Focus::Details,
        );

        let mut y = inner.y;
        let header = item.folder.as_deref().map_or_else(
            || item.kind.name().to_lowercase(),
            |folder| {
                format!(
                    "{} · {}",
                    item.kind.name().to_lowercase(),
                    crate::term::sanitize(folder)
                )
            },
        );
        frame.put(inner.x, y, &header, DIM, inner.right());
        if item.reprompt {
            let x = inner.right().saturating_sub(18);
            frame.put(x, y, "master pw reprompt", DIM, inner.right());
        }
        y += 2;

        let label_width = item
            .rows
            .iter()
            .map(|row| crate::term::width(&row.label))
            .max()
            .unwrap_or(0)
            .min(inner.width / 3);
        let rows_height = inner.bottom().saturating_sub(y);
        self.detail_offset = scroll(
            self.detail_offset,
            self.detail_selected,
            rows_height,
            item.rows.len(),
        );
        let revealed = self.revealed.as_ref().map(|(_, revealed)| revealed);
        for (i, row) in item
            .rows
            .iter()
            .enumerate()
            .skip(self.detail_offset)
            .take(rows_height)
        {
            let selected =
                self.focus == Focus::Details && i == self.detail_selected;
            if selected {
                frame.fill(inner.x, y, inner.width, SELECTED);
            }
            let label = crate::term::sanitize(&row.label);
            let label = crate::term::truncate(&label, label_width);
            let label_x = inner.x + label_width - crate::term::width(label);
            frame.put(
                label_x,
                y,
                label,
                if selected { SELECTED } else { DIM },
                inner.right(),
            );
            let x = inner.x + label_width + 2;
            let style = if selected { SELECTED } else { PLAIN };
            match &row.value {
                Value::Plain(value) => {
                    frame.put(
                        x,
                        y,
                        &crate::term::sanitize(value),
                        style,
                        inner.right(),
                    );
                }
                Value::Secret(_) => {
                    let value = revealed.and_then(|revealed| {
                        revealed.get(i).cloned().flatten()
                    });
                    let value = value.as_deref().map_or_else(
                        || "••••••••".to_string(),
                        crate::term::sanitize,
                    );
                    frame.put(x, y, &value, style, inner.right());
                }
                Value::Totp(_) => match &self.totp {
                    Some((id, Totp::Secret(secret))) if *id == item.id => {
                        match crate::commands::totp_now(secret) {
                            Ok((code, remaining)) => {
                                let x = frame.put(
                                    x,
                                    y,
                                    &code,
                                    if selected { SELECTED } else { TOTP },
                                    inner.right(),
                                );
                                frame.put(
                                    x + 2,
                                    y,
                                    &format!("{remaining}s"),
                                    if selected { SELECTED } else { DIM },
                                    inner.right(),
                                );
                            }
                            Err(e) => {
                                frame.put(
                                    x,
                                    y,
                                    &crate::term::sanitize(&format!("{e}")),
                                    ERROR,
                                    inner.right(),
                                );
                            }
                        }
                    }
                    _ => {
                        frame.put(
                            x,
                            y,
                            "^T to copy",
                            if selected { SELECTED } else { DIM },
                            inner.right(),
                        );
                    }
                },
            }
            y += 1;
        }

        if let Some(notes) = &item.notes {
            if y < inner.bottom() {
                y += usize::from(!item.rows.is_empty());
                for line in
                    notes.lines().flat_map(|line| wrap(line, inner.width))
                {
                    if y >= inner.bottom() {
                        break;
                    }
                    frame.put(inner.x, y, &line, PLAIN, inner.right());
                    y += 1;
                }
            }
        }
    }

    fn render_bottom(&self, frame: &mut Frame, y: usize) {
        let width = frame.width;
        if let Some((message, error, _)) = &self.status {
            frame.put(
                1,
                y,
                &crate::term::sanitize(message),
                if *error { ERROR } else { ACCENT },
                width,
            );
            return;
        }
        let hints: &[(&str, &str)] = match self.focus {
            Focus::Details => &[
                ("↵", "copy field"),
                ("^R", "reveal"),
                ("⇥", "back"),
                ("Esc", "back"),
            ],
            Focus::Sidebar => &[("↑↓", "filter"), ("↵", "list")],
            Focus::List => &[
                ("↵", "actions"),
                ("^P", "copy password"),
                ("^U", "user"),
                ("^T", "totp"),
                ("⇥", "fields"),
                ("^R", "reveal"),
                ("^O", "open"),
                ("^S", "sync"),
                ("^L", "lock"),
                ("F1", "help"),
            ],
        };
        let mut x = 1;
        for (key, label) in hints {
            if x + crate::term::width(key) + crate::term::width(label) + 3
                > width
            {
                break;
            }
            x = frame.put(x, y, key, ACCENT_BOLD, width);
            x = frame.put(x + 1, y, label, DIM, width) + 2;
        }
    }

    fn render_actions(&self, frame: &mut Frame, selected: usize) {
        let Some(item) = self.current() else {
            return;
        };
        let actions = self.actions();
        let width = actions
            .iter()
            .map(|(_, label, _)| crate::term::width(label) + 8)
            .max()
            .unwrap_or(0)
            .max(36)
            .min(frame.width.saturating_sub(4));
        let height = (actions.len() + 4).min(frame.height.saturating_sub(2));
        let rect = Rect::new(
            (frame.width.saturating_sub(width)) / 2,
            (frame.height.saturating_sub(height)) / 2,
            width,
            height,
        );
        frame.clear(rect);
        let inner =
            frame.border(rect, &crate::term::sanitize(&item.name), true);
        for (i, (_, label, key)) in
            actions.iter().enumerate().take(inner.height)
        {
            let y = inner.y + i;
            let style = if i == selected { SELECTED } else { PLAIN };
            if i == selected {
                frame.fill(inner.x, y, inner.width, style);
            }
            frame.put(inner.x + 1, y, label, style, inner.right());
            let key_x =
                inner.right().saturating_sub(crate::term::width(key) + 1);
            frame.put(
                key_x,
                y,
                key,
                if i == selected { style } else { ACCENT },
                inner.right(),
            );
        }
        if inner.height > actions.len() + 1 {
            let y = inner.bottom() - 1;
            let mut x = inner.x + 1;
            for (key, label) in
                [("↑↓", "choose"), ("↵", "do it"), ("Esc", "close")]
            {
                x = frame.put(x, y, key, ACCENT_BOLD, inner.right());
                x = frame.put(x + 1, y, label, DIM, inner.right()) + 2;
            }
        }
    }
}

fn render_help(frame: &mut Frame) {
    let lines = [
        ("type", "search (fuzzy, words in any order)"),
        ("↑↓ PgUp PgDn", "move"),
        ("↵", "actions for the entry"),
        ("^P", "copy the password (card number, ssh key)"),
        ("^U", "copy the username"),
        ("^T", "copy the totp code"),
        ("⇥ / →", "fields of the entry, ↵ copies one"),
        ("← / ⇧⇥", "filter by type or folder"),
        ("^R", "show or hide the secrets"),
        ("^O", "open the web address"),
        ("^S", "sync with the server"),
        ("^L", "lock and quit"),
        ("^W", "delete a word of the search"),
        ("Esc", "clear the search, or quit"),
    ];
    let width = 60.min(frame.width.saturating_sub(4));
    let height = (lines.len() + 3).min(frame.height.saturating_sub(2));
    let rect = Rect::new(
        (frame.width.saturating_sub(width)) / 2,
        (frame.height.saturating_sub(height)) / 2,
        width,
        height,
    );
    frame.clear(rect);
    let inner = frame.border(rect, "Keys", true);
    for (i, (key, text)) in lines
        .iter()
        .enumerate()
        .take(inner.height.saturating_sub(1))
    {
        let y = inner.y + i;
        frame.put(inner.x + 1, y, key, ACCENT_BOLD, inner.right());
        frame.put(inner.x + 15, y, text, PLAIN, inner.right());
    }
}

// the new scroll offset which keeps the selected line visible
fn scroll(
    offset: usize,
    selected: usize,
    height: usize,
    len: usize,
) -> usize {
    if height == 0 {
        return 0;
    }
    let offset = offset.min(len.saturating_sub(height));
    if selected < offset {
        selected
    } else if selected >= offset + height {
        selected + 1 - height
    } else {
        offset
    }
}

// splits a line into pieces which fit into the given width
fn wrap(line: &str, width: usize) -> Vec<String> {
    let line = crate::term::sanitize(line);
    if width == 0 {
        return vec![];
    }
    let mut lines = vec![];
    let mut rest = line.as_str();
    loop {
        let piece = crate::term::truncate(rest, width);
        if piece.len() == rest.len() || piece.is_empty() {
            lines.push(rest.to_string());
            return lines;
        }
        // prefer breaking at a space, unless the piece ends at one anyway
        let piece = if rest[piece.len()..].starts_with(' ') {
            piece
        } else {
            piece
                .rfind(' ')
                .filter(|&i| i > 0)
                .map_or(piece, |i| &piece[..i])
        };
        lines.push(piece.to_string());
        rest = rest[piece.len()..].trim_start_matches(' ');
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Style {
    fg: Option<u8>,
    bold: bool,
    dim: bool,
    reverse: bool,
}

impl Style {
    const fn dimmed(self) -> Self {
        if self.reverse {
            self
        } else {
            Self { dim: true, ..self }
        }
    }

    fn sgr(self) -> String {
        let mut codes = vec!["0".to_string()];
        if self.bold {
            codes.push("1".to_string());
        }
        if self.dim {
            codes.push("2".to_string());
        }
        if self.reverse {
            codes.push("7".to_string());
        }
        if let Some(fg) = self.fg {
            codes.push((30 + u32::from(fg)).to_string());
        }
        format!("\x1b[{}m", codes.join(";"))
    }
}

// the terminal's own palette, so that the tui fits its color scheme
const PLAIN: Style = Style {
    fg: None,
    bold: false,
    dim: false,
    reverse: false,
};
const BOLD: Style = Style {
    bold: true,
    ..PLAIN
};
const DIM: Style = Style { dim: true, ..PLAIN };
const REVERSE: Style = Style {
    reverse: true,
    ..PLAIN
};
const SELECTED: Style = REVERSE;
const ACCENT: Style = Style {
    fg: Some(6),
    ..PLAIN
};
const ACCENT_BOLD: Style = Style {
    bold: true,
    ..ACCENT
};
const HEADING: Style = Style {
    bold: true,
    dim: true,
    ..PLAIN
};
const FOLDER: Style = Style {
    fg: Some(4),
    ..PLAIN
};
const TOTP: Style = Style {
    fg: Some(2),
    bold: true,
    ..PLAIN
};
const ERROR: Style = Style {
    fg: Some(1),
    bold: true,
    ..PLAIN
};

#[derive(Debug, Clone, Copy)]
struct Rect {
    x: usize,
    y: usize,
    width: usize,
    height: usize,
}

impl Rect {
    const fn new(x: usize, y: usize, width: usize, height: usize) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    const fn right(&self) -> usize {
        self.x + self.width
    }

    const fn bottom(&self) -> usize {
        self.y + self.height
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Cell {
    // a character plus any zero width characters following it, or empty for
    // the second column of a wide character
    text: String,
    style: Style,
}

// places a character taking width columns at x. a wide character which is
// partly overwritten has its other half blanked, so that the rest of the line
// stays in place.
fn place(
    row: &mut [Cell],
    x: usize,
    text: String,
    width: usize,
    style: Style,
) {
    if row[x].text.is_empty() && x > 0 {
        row[x - 1].text = " ".to_string();
    }
    if row.get(x + width).is_some_and(|cell| cell.text.is_empty()) {
        row[x + width].text = " ".to_string();
    }
    row[x] = Cell { text, style };
    if width == 2 {
        row[x + 1] = Cell {
            text: String::new(),
            style,
        };
    }
}

struct Frame {
    width: usize,
    height: usize,
    cells: Vec<Vec<Cell>>,
}

impl Frame {
    fn new(width: usize, height: usize) -> Self {
        let blank = Cell {
            text: " ".to_string(),
            style: PLAIN,
        };
        Self {
            width,
            height,
            cells: vec![vec![blank; width]; height],
        }
    }

    // writes text starting at x, without going past max_x, and returns the
    // column after it
    fn put(
        &mut self,
        mut x: usize,
        y: usize,
        text: &str,
        style: Style,
        max_x: usize,
    ) -> usize {
        let max_x = max_x.min(self.width);
        if y >= self.height {
            return x;
        }
        let row = &mut self.cells[y];
        for c in text.chars() {
            match crate::term::char_width(c) {
                0 => {
                    if x > 0 && x <= max_x {
                        row[x - 1].text.push(c);
                    }
                }
                w => {
                    if x + w > max_x {
                        break;
                    }
                    place(row, x, c.to_string(), w, style);
                    x += w;
                }
            }
        }
        x
    }

    fn fill(&mut self, x: usize, y: usize, width: usize, style: Style) {
        if y >= self.height {
            return;
        }
        for cell in self.cells[y].iter_mut().skip(x).take(width) {
            cell.style = style;
        }
    }

    fn clear(&mut self, rect: Rect) {
        for y in rect.y..rect.bottom().min(self.height) {
            for x in rect.x..rect.right().min(self.width) {
                place(&mut self.cells[y], x, " ".to_string(), 1, PLAIN);
            }
        }
    }

    // draws a box with a title, and returns the area inside it
    fn border(&mut self, rect: Rect, title: &str, focused: bool) -> Rect {
        if rect.width < 2 || rect.height < 2 {
            return Rect::new(rect.x, rect.y, 0, 0);
        }
        let style = if focused { ACCENT } else { DIM };
        let right = rect.right() - 1;
        let bottom = rect.bottom() - 1;
        for x in rect.x + 1..right {
            self.put(x, rect.y, "─", style, self.width);
            self.put(x, bottom, "─", style, self.width);
        }
        for y in rect.y + 1..bottom {
            self.put(rect.x, y, "│", style, self.width);
            self.put(right, y, "│", style, self.width);
        }
        self.put(rect.x, rect.y, "╭", style, self.width);
        self.put(right, rect.y, "╮", style, self.width);
        self.put(rect.x, bottom, "╰", style, self.width);
        self.put(right, bottom, "╯", style, self.width);
        if !title.is_empty() && rect.width > 6 {
            let title_style = if focused { ACCENT_BOLD } else { BOLD };
            let x = self.put(rect.x + 2, rect.y, " ", style, right - 1);
            let x = self.put(x, rect.y, title, title_style, right - 2);
            self.put(x, rect.y, " ", style, right - 1);
        }
        Rect::new(rect.x + 2, rect.y + 1, rect.width - 4, rect.height - 2)
    }
}

// what is currently on the terminal, so that only changed lines are redrawn
#[derive(Default)]
struct Screen {
    lines: Vec<String>,
    pane_height: usize,
    sidebar_shown: bool,
}

impl Screen {
    fn invalidate(&mut self) {
        self.lines.clear();
    }

    fn show(&mut self, frame: &Frame) -> std::io::Result<()> {
        if self.lines.len() != frame.height {
            self.lines = vec![String::new(); frame.height];
            crate::term::write_stdout(b"\x1b[2J")?;
        }
        let mut out = String::new();
        for (y, row) in frame.cells.iter().enumerate() {
            let mut line = String::new();
            let mut style = None;
            for cell in row {
                if style != Some(cell.style) {
                    line.push_str(&cell.style.sgr());
                    style = Some(cell.style);
                }
                line.push_str(&cell.text);
            }
            line.push_str("\x1b[0m");
            if self.lines[y] != line {
                write!(out, "\x1b[{};1H", y + 1).unwrap();
                out.push_str(&line);
                self.lines[y] = line;
            }
        }
        if !out.is_empty() {
            crate::term::write_stdout(out.as_bytes())?;
        }
        Ok(())
    }
}

pub fn run() -> anyhow::Result<()> {
    // unlock before taking over the terminal, so that pinentry can use it
    crate::commands::unlock()?;
    let items = load_items()?;
    let mut term = Terminal::enter()?;
    let mut app = App::new(items);
    let res = app.run(&mut term);
    drop(term);
    if let Err(e) = app.clear_clipboard() {
        eprintln!("{e:#}");
    }
    res
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_wrap() {
        assert_eq!(wrap("abc def ghi", 7), vec!["abc def", "ghi"]);
        assert_eq!(wrap("abcdefghij", 4), vec!["abcd", "efgh", "ij"]);
        assert_eq!(wrap("", 4), vec![""]);
    }

    #[test]
    fn test_wide_characters() {
        let mut frame = Frame::new(6, 1);
        frame.put(0, 0, "日本語", PLAIN, 6);
        // overwriting the second half of 日 and the first half of 本
        frame.put(1, 0, "ab", PLAIN, 6);
        let text: String = frame.cells[0]
            .iter()
            .map(|cell| cell.text.as_str())
            .collect();
        assert_eq!(text, " ab 語");
        assert_eq!(crate::term::width(&text), 6);
    }

    #[test]
    fn test_scroll() {
        assert_eq!(scroll(0, 5, 3, 10), 3);
        assert_eq!(scroll(4, 2, 3, 10), 2);
        assert_eq!(scroll(2, 3, 3, 10), 2);
        // shrinking lists don't leave empty space at the end
        assert_eq!(scroll(8, 2, 5, 4), 0);
    }
}
