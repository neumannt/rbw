use std::{fmt::Write as _, io::Write as _, os::unix::ffi::OsStrExt as _};

use anyhow::Context as _;

// The default number of seconds the generated TOTP
// code lasts for before a new one must be generated
const TOTP_DEFAULT_STEP: u64 = 30;

const MISSING_CONFIG_HELP: &str =
    "Before using rbw, you must configure the email address you would like to \
    use to log in to the server by running:\n\n    \
        rbw config set email <email>\n\n\
    Additionally, if you are using a self-hosted installation, you should \
    run:\n\n    \
        rbw config set base_url <url>\n\n\
    and, if your server has a non-default identity url:\n\n    \
        rbw config set identity_url <url>\n";

#[derive(Debug, Clone)]
pub enum Needle {
    Name(String),
    Uri(url::Url),
    Uuid(rbw::uuid::Uuid, String),
}

impl std::fmt::Display for Needle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match &self {
            Self::Name(name) => name.clone(),
            Self::Uri(uri) => uri.to_string(),
            Self::Uuid(_, s) => s.clone(),
        };
        write!(f, "{value}")
    }
}

#[allow(clippy::unnecessary_wraps)]
pub fn parse_needle(arg: &str) -> Result<Needle, std::convert::Infallible> {
    if let Some(uuid) = rbw::uuid::Uuid::parse(arg) {
        return Ok(Needle::Uuid(uuid, arg.to_string()));
    }
    if let Ok(url) = url::Url::parse(arg) {
        if url.is_special() {
            return Ok(Needle::Uri(url));
        }
    }

    Ok(Needle::Name(arg.to_string()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Field {
    Notes,
    Username,
    Password,
    Totp,
    Uris,
    IdentityName,
    City,
    State,
    PostalCode,
    Country,
    Phone,
    Ssn,
    License,
    Passport,
    CardNumber,
    Expiration,
    ExpMonth,
    ExpYear,
    Cvv,
    Cardholder,
    Brand,
    Name,
    Email,
    Address,
    Address1,
    Address2,
    Address3,
    Fingerprint,
    PublicKey,
    PrivateKey,
    Title,
    FirstName,
    MiddleName,
    LastName,
}

impl std::str::FromStr for Field {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "notes" | "note" => Self::Notes,
            "username" | "user" => Self::Username,
            "password" => Self::Password,
            "totp" | "code" => Self::Totp,
            "uris" | "urls" | "sites" => Self::Uris,
            "identityname" => Self::IdentityName,
            "city" => Self::City,
            "state" => Self::State,
            "postcode" | "zipcode" | "zip" => Self::PostalCode,
            "country" => Self::Country,
            "phone" => Self::Phone,
            "ssn" => Self::Ssn,
            "license" => Self::License,
            "passport" => Self::Passport,
            "number" | "card" => Self::CardNumber,
            "exp" => Self::Expiration,
            "exp_month" | "month" => Self::ExpMonth,
            "exp_year" | "year" => Self::ExpYear,
            // the word "code" got preceeded by Totp
            "cvv" => Self::Cvv,
            "cardholder" | "cardholder_name" => Self::Cardholder,
            "brand" | "type" => Self::Brand,
            "name" => Self::Name,
            "email" => Self::Email,
            "address1" => Self::Address1,
            "address2" => Self::Address2,
            "address3" => Self::Address3,
            "address" => Self::Address,
            "fingerprint" => Self::Fingerprint,
            "public_key" => Self::PublicKey,
            "private_key" => Self::PrivateKey,
            "title" => Self::Title,
            "first_name" => Self::FirstName,
            "middle_name" => Self::MiddleName,
            "last_name" => Self::LastName,
            _ => anyhow::bail!("unknown field {s}"),
        })
    }
}

impl Field {
    fn as_str(&self) -> &str {
        match self {
            Self::Notes => "notes",
            Self::Username => "username",
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Uris => "uris",
            Self::IdentityName => "identityname",
            Self::City => "city",
            Self::State => "state",
            Self::PostalCode => "postcode",
            Self::Country => "country",
            Self::Phone => "phone",
            Self::Ssn => "ssn",
            Self::License => "license",
            Self::Passport => "passport",
            Self::CardNumber => "number",
            Self::Expiration => "exp",
            Self::ExpMonth => "exp_month",
            Self::ExpYear => "exp_year",
            Self::Cvv => "cvv",
            Self::Cardholder => "cardholder",
            Self::Brand => "brand",
            Self::Name => "name",
            Self::Email => "email",
            Self::Address1 => "address1",
            Self::Address2 => "address2",
            Self::Address3 => "address3",
            Self::Address => "address",
            Self::Fingerprint => "fingerprint",
            Self::PublicKey => "public_key",
            Self::PrivateKey => "private_key",
            Self::Title => "title",
            Self::FirstName => "first_name",
            Self::MiddleName => "middle_name",
            Self::LastName => "last_name",
        }
    }
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, serde::Serialize)]
struct DecryptedListCipher {
    id: String,
    name: Option<String>,
    user: Option<String>,
    folder: Option<String>,
    uris: Option<Vec<String>>,
    #[serde(rename = "type")]
    entry_type: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedSearchCipher {
    id: String,
    #[serde(rename = "type")]
    entry_type: String,
    folder: Option<String>,
    name: String,
    user: Option<String>,
    uris: Vec<(String, Option<rbw::api::UriMatchType>)>,
    fields: Vec<String>,
    notes: Option<String>,
}

impl DecryptedSearchCipher {
    fn display_name(&self) -> String {
        self.user.as_ref().map_or_else(
            || self.name.clone(),
            |user| format!("{user}@{}", self.name),
        )
    }

    fn matches(
        &self,
        needle: &Needle,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
        strict_username: bool,
        strict_folder: bool,
        exact: bool,
    ) -> bool {
        let match_str = match (ignore_case, exact) {
            (true, true) => |field: &str, search_term: &str| {
                field.to_lowercase() == search_term.to_lowercase()
            },
            (true, false) => |field: &str, search_term: &str| {
                field.to_lowercase().contains(&search_term.to_lowercase())
            },
            (false, true) => {
                |field: &str, search_term: &str| field == search_term
            }
            (false, false) => {
                |field: &str, search_term: &str| field.contains(search_term)
            }
        };

        match (self.folder.as_deref(), folder) {
            (Some(folder), Some(given_folder)) => {
                if !match_str(folder, given_folder) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_folder {
                    return false;
                }
            }
            (None, Some(_)) => {
                return false;
            }
            (None, None) => {}
        }

        match (&self.user, username) {
            (Some(username), Some(given_username)) => {
                if !match_str(username, given_username) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_username {
                    return false;
                }
            }
            (None, Some(_)) => {
                return false;
            }
            (None, None) => {}
        }

        match needle {
            Needle::Uuid(uuid, s) => {
                if rbw::uuid::Uuid::parse(&self.id) != Some(*uuid)
                    && !match_str(&self.name, s)
                {
                    return false;
                }
            }
            Needle::Name(name) => {
                if !match_str(&self.name, name) {
                    return false;
                }
            }
            Needle::Uri(given_uri) => {
                if self.uris.iter().all(|(uri, match_type)| {
                    !matches_url(uri, *match_type, given_uri)
                }) {
                    return false;
                }
            }
        }

        true
    }

    fn search_match(&self, term: &str, folder: Option<&str>) -> bool {
        if let Some(folder) = folder {
            if self.folder.as_deref() != Some(folder) {
                return false;
            }
        }

        let mut fields = vec![self.name.clone()];
        if let Some(notes) = &self.notes {
            fields.push(notes.clone());
        }
        if let Some(user) = &self.user {
            fields.push(user.clone());
        }
        fields.extend(self.uris.iter().map(|(uri, _)| uri).cloned());
        fields.extend(self.fields.iter().cloned());

        for field in fields {
            if field.to_lowercase().contains(&term.to_lowercase()) {
                return true;
            }
        }

        false
    }
}

impl From<DecryptedSearchCipher> for DecryptedListCipher {
    fn from(value: DecryptedSearchCipher) -> Self {
        Self {
            id: value.id,
            entry_type: Some(value.entry_type),
            name: Some(value.name),
            user: value.user,
            folder: value.folder,
            uris: Some(value.uris.into_iter().map(|(s, _)| s).collect()),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedCipher {
    id: String,
    folder: Option<String>,
    name: String,
    data: DecryptedData,
    fields: Vec<DecryptedField>,
    notes: Option<String>,
    history: Vec<DecryptedHistoryEntry>,
}

impl DecryptedCipher {
    fn display_short(
        &self,
        desc: &str,
        clipboard: crate::clipboard::Mode,
    ) -> bool {
        match &self.data {
            DecryptedData::Login { password, .. } => {
                password.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no password");
                        false
                    },
                    |password| val_display_or_store(clipboard, password),
                )
            }
            DecryptedData::Card { number, .. } => {
                number.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no card number");
                        false
                    },
                    |number| val_display_or_store(clipboard, number),
                )
            }
            DecryptedData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                let names: Vec<_> =
                    [title, first_name, middle_name, last_name]
                        .iter()
                        .copied()
                        .flatten()
                        .cloned()
                        .collect();
                if names.is_empty() {
                    eprintln!("entry for '{desc}' had no name");
                    false
                } else {
                    val_display_or_store(clipboard, &names.join(" "))
                }
            }
            DecryptedData::SecureNote => self.notes.as_ref().map_or_else(
                || {
                    eprintln!("entry for '{desc}' had no notes");
                    false
                },
                |notes| val_display_or_store(clipboard, notes),
            ),
            DecryptedData::SshKey { public_key, .. } => {
                public_key.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no public key");
                        false
                    },
                    |public_key| val_display_or_store(clipboard, public_key),
                )
            }
        }
    }

    fn display_field(
        &self,
        desc: &str,
        field: &str,
        clipboard: crate::clipboard::Mode,
    ) {
        let field = field.to_lowercase();
        let field = field.as_str();
        match &self.data {
            DecryptedData::Login {
                username,
                totp,
                uris,
                ..
            } => match field.parse() {
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                Ok(Field::Username) => {
                    if let Some(username) = &username {
                        val_display_or_store(clipboard, username);
                    }
                }
                Ok(Field::Totp) => {
                    if let Some(totp) = totp {
                        match generate_totp(totp) {
                            Ok(code) => {
                                val_display_or_store(clipboard, &code);
                            }
                            Err(e) => {
                                eprintln!("{e}");
                            }
                        }
                    }
                }
                Ok(Field::Uris) => {
                    if let Some(uris) = uris {
                        let uri_strs: Vec<_> =
                            uris.iter().map(|uri| uri.uri.clone()).collect();
                        val_display_or_store(clipboard, &uri_strs.join("\n"));
                    }
                }
                Ok(Field::Password) => {
                    self.display_short(desc, clipboard);
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => match field.parse() {
                Ok(Field::CardNumber) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::Expiration) => {
                    if let (Some(month), Some(year)) = (exp_month, exp_year) {
                        val_display_or_store(
                            clipboard,
                            &format!("{month}/{year}"),
                        );
                    }
                }
                Ok(Field::ExpMonth) => {
                    if let Some(exp_month) = exp_month {
                        val_display_or_store(clipboard, exp_month);
                    }
                }
                Ok(Field::ExpYear) => {
                    if let Some(exp_year) = exp_year {
                        val_display_or_store(clipboard, exp_year);
                    }
                }
                Ok(Field::Cvv) => {
                    if let Some(code) = code {
                        val_display_or_store(clipboard, code);
                    }
                }
                Ok(Field::Name | Field::Cardholder) => {
                    if let Some(cardholder_name) = cardholder_name {
                        val_display_or_store(clipboard, cardholder_name);
                    }
                }
                Ok(Field::Brand) => {
                    if let Some(brand) = brand {
                        val_display_or_store(clipboard, brand);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::Identity {
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
                ..
            } => match field.parse() {
                Ok(Field::Name) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::Email) => {
                    if let Some(email) = email {
                        val_display_or_store(clipboard, email);
                    }
                }
                Ok(Field::Address) => {
                    let mut strs = vec![];
                    if let Some(address1) = address1 {
                        strs.push(address1.clone());
                    }
                    if let Some(address2) = address2 {
                        strs.push(address2.clone());
                    }
                    if let Some(address3) = address3 {
                        strs.push(address3.clone());
                    }
                    if !strs.is_empty() {
                        val_display_or_store(clipboard, &strs.join("\n"));
                    }
                }
                Ok(Field::City) => {
                    if let Some(city) = city {
                        val_display_or_store(clipboard, city);
                    }
                }
                Ok(Field::State) => {
                    if let Some(state) = state {
                        val_display_or_store(clipboard, state);
                    }
                }
                Ok(Field::PostalCode) => {
                    if let Some(postal_code) = postal_code {
                        val_display_or_store(clipboard, postal_code);
                    }
                }
                Ok(Field::Country) => {
                    if let Some(country) = country {
                        val_display_or_store(clipboard, country);
                    }
                }
                Ok(Field::Phone) => {
                    if let Some(phone) = phone {
                        val_display_or_store(clipboard, phone);
                    }
                }
                Ok(Field::Ssn) => {
                    if let Some(ssn) = ssn {
                        val_display_or_store(clipboard, ssn);
                    }
                }
                Ok(Field::License) => {
                    if let Some(license_number) = license_number {
                        val_display_or_store(clipboard, license_number);
                    }
                }
                Ok(Field::Passport) => {
                    if let Some(passport_number) = passport_number {
                        val_display_or_store(clipboard, passport_number);
                    }
                }
                Ok(Field::Username) => {
                    if let Some(username) = username {
                        val_display_or_store(clipboard, username);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::SecureNote => match field.parse() {
                Ok(Field::Notes) => {
                    self.display_short(desc, clipboard);
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::SshKey {
                fingerprint,
                private_key,
                ..
            } => match field.parse() {
                Ok(Field::Fingerprint) => {
                    if let Some(fingerprint) = fingerprint {
                        val_display_or_store(clipboard, fingerprint);
                    }
                }
                Ok(Field::PublicKey) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::PrivateKey) => {
                    if let Some(private_key) = private_key {
                        val_display_or_store(clipboard, private_key);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
        }
    }

    /// Displays all fields of the entry. With `Secrets::Hide`, the password,
    /// the TOTP secret, hidden custom fields, and the card number and CVV are
    /// replaced by a command which copies them.
    fn display_long(
        &self,
        desc: &str,
        clipboard: crate::clipboard::Mode,
        secrets: &Secrets,
    ) {
        match &self.data {
            DecryptedData::Login {
                username,
                password,
                totp,
                uris,
                ..
            } => {
                let mut displayed = match secrets {
                    Secrets::Show => self.display_short(desc, clipboard),
                    Secrets::Hide { .. } => secrets
                        .display_main_hint("Password", password.as_deref()),
                };
                displayed |=
                    display_field("Username", username.as_deref(), clipboard);
                displayed |= match secrets {
                    Secrets::Show => display_field(
                        "TOTP Secret",
                        totp.as_deref(),
                        clipboard,
                    ),
                    Secrets::Hide { .. } => secrets.display_hint(
                        "TOTP",
                        totp.as_deref(),
                        "code",
                        "",
                    ),
                };

                if let Some(uris) = uris {
                    for uri in uris {
                        displayed |=
                            display_field("URI", Some(&uri.uri), clipboard);
                        let match_type =
                            uri.match_type.map(|ty| format!("{ty}"));
                        displayed |= display_field(
                            "Match type",
                            match_type.as_deref(),
                            clipboard,
                        );
                    }
                }

                for field in &self.fields {
                    displayed |=
                        display_custom_field(field, clipboard, secrets);
                }

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
            } => {
                let mut displayed = false;

                displayed |= match secrets {
                    Secrets::Show => self.display_short(desc, clipboard),
                    Secrets::Hide { .. } => {
                        secrets.display_main_hint("Number", number.as_deref())
                    }
                };
                if let (Some(exp_month), Some(exp_year)) =
                    (exp_month, exp_year)
                {
                    println!("Expiration: {exp_month}/{exp_year}");
                    displayed = true;
                }
                displayed |= match secrets {
                    Secrets::Show => {
                        display_field("CVV", code.as_deref(), clipboard)
                    }
                    Secrets::Hide { .. } => secrets.display_hint(
                        "CVV",
                        code.as_deref(),
                        "get",
                        " -f cvv",
                    ),
                };
                displayed |= display_field(
                    "Name",
                    cardholder_name.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Brand", brand.as_deref(), clipboard);

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::Identity {
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
                ..
            } => {
                let mut displayed = self.display_short(desc, clipboard);

                displayed |=
                    display_field("Address", address1.as_deref(), clipboard);
                displayed |=
                    display_field("Address", address2.as_deref(), clipboard);
                displayed |=
                    display_field("Address", address3.as_deref(), clipboard);
                displayed |=
                    display_field("City", city.as_deref(), clipboard);
                displayed |=
                    display_field("State", state.as_deref(), clipboard);
                displayed |= display_field(
                    "Postcode",
                    postal_code.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Country", country.as_deref(), clipboard);
                displayed |=
                    display_field("Phone", phone.as_deref(), clipboard);
                displayed |=
                    display_field("Email", email.as_deref(), clipboard);
                displayed |= display_field("SSN", ssn.as_deref(), clipboard);
                displayed |= display_field(
                    "License",
                    license_number.as_deref(),
                    clipboard,
                );
                displayed |= display_field(
                    "Passport",
                    passport_number.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Username", username.as_deref(), clipboard);

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::SecureNote => {
                self.display_short(desc, clipboard);
            }
            DecryptedData::SshKey { fingerprint, .. } => {
                let mut displayed = self.display_short(desc, clipboard);
                displayed |= display_field(
                    "Fingerprint",
                    fingerprint.as_deref(),
                    clipboard,
                );

                for field in &self.fields {
                    displayed |=
                        display_custom_field(field, clipboard, secrets);
                }

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
        }
    }

    /// This implementation mirror the `fn display_fied` method on which field to list
    fn display_fields_list(&self) {
        match &self.data {
            DecryptedData::Login {
                username,
                password,
                totp,
                uris,
                ..
            } => {
                if username.is_some() {
                    println!("{}", Field::Username);
                }
                if totp.is_some() {
                    println!("{}", Field::Totp);
                }
                if uris.is_some() {
                    println!("{}", Field::Uris);
                }
                if password.is_some() {
                    println!("{}", Field::Password);
                }
            }
            DecryptedData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                if number.is_some() {
                    println!("{}", Field::CardNumber);
                }
                if exp_month.is_some() {
                    println!("{}", Field::ExpMonth);
                }
                if exp_year.is_some() {
                    println!("{}", Field::ExpYear);
                }
                if code.is_some() {
                    println!("{}", Field::Cvv);
                }
                if cardholder_name.is_some() {
                    println!("{}", Field::Cardholder);
                }
                if brand.is_some() {
                    println!("{}", Field::Brand);
                }
            }

            DecryptedData::Identity {
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
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                if [title, first_name, middle_name, last_name]
                    .iter()
                    .any(|f| f.is_some())
                {
                    // the display_field combines all these fields together.
                    println!("name");
                }
                if email.is_some() {
                    println!("{}", Field::Email);
                }
                if [address1, address2, address3].iter().any(|f| f.is_some())
                {
                    // the display_field combines all these fields together.
                    println!("address");
                }
                if city.is_some() {
                    println!("{}", Field::City);
                }
                if state.is_some() {
                    println!("{}", Field::State);
                }
                if postal_code.is_some() {
                    println!("{}", Field::PostalCode);
                }
                if country.is_some() {
                    println!("{}", Field::Country);
                }
                if phone.is_some() {
                    println!("{}", Field::Phone);
                }
                if ssn.is_some() {
                    println!("{}", Field::Ssn);
                }
                if license_number.is_some() {
                    println!("{}", Field::License);
                }
                if passport_number.is_some() {
                    println!("{}", Field::Passport);
                }
                if username.is_some() {
                    println!("{}", Field::Username);
                }
            }

            DecryptedData::SecureNote => (), // handled at the end
            DecryptedData::SshKey {
                fingerprint,
                public_key,
                ..
            } => {
                if fingerprint.is_some() {
                    println!("{}", Field::Fingerprint);
                }
                if public_key.is_some() {
                    println!("{}", Field::PublicKey);
                }
            }
        }

        if self.notes.is_some() {
            println!("{}", Field::Notes);
        }
        for f in &self.fields {
            if let Some(name) = &f.name {
                println!("{name}");
            }
        }
    }

    fn display_json(&self, desc: &str) -> anyhow::Result<()> {
        serde_json::to_writer_pretty(std::io::stdout(), &self)
            .context(format!("failed to write entry '{desc}' to stdout"))?;
        println!();

        Ok(())
    }
}

/// How `DecryptedCipher::display_long` treats secret fields
enum Secrets {
    Show,
    Hide {
        /// `rbw` arguments selecting the entry, for the displayed hints
        entry_args: String,
        /// whether the main secret was already copied to the clipboard
        copied: bool,
    },
}

impl Secrets {
    /// Like `display_hint`, for the secret which `rbw get` (and `rbw show
    /// --clipboard`) copies.
    fn display_main_hint(&self, name: &str, value: Option<&str>) -> bool {
        if let Self::Hide { copied: true, .. } = self {
            if value.is_some() {
                println!("{name}: (copied to clipboard)");
                return true;
            }
        }
        self.display_hint(name, value, "get", "")
    }

    /// Displays a placeholder for a hidden secret, with the command to copy
    /// it, if the secret is set.
    fn display_hint(
        &self,
        name: &str,
        value: Option<&str>,
        subcommand: &str,
        extra_args: &str,
    ) -> bool {
        let Self::Hide { entry_args, .. } = self else {
            return false;
        };
        if value.is_none() {
            return false;
        }
        let copy = if cfg!(feature = "clipboard") {
            " -c"
        } else {
            ""
        };
        println!(
            "{name}: (hidden, use `rbw {subcommand} {entry_args}{extra_args}{copy}`)"
        );
        true
    }
}

/// Quotes `s` for use as a single shell word, if necessary
fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.,:/@%+=".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn val_display_or_store(
    clipboard: crate::clipboard::Mode,
    password: &str,
) -> bool {
    if clipboard == crate::clipboard::Mode::Off {
        println!("{password}");
        true
    } else {
        match crate::clipboard::store(password, clipboard) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("{e}");
                false
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
#[cfg_attr(test, derive(Eq, PartialEq))]
enum DecryptedData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Option<Vec<DecryptedUri>>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        public_key: Option<String>,
        fingerprint: Option<String>,
        private_key: Option<String>,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedField {
    name: Option<String>,
    value: Option<String>,
    #[serde(serialize_with = "serialize_field_type", rename = "type")]
    ty: Option<rbw::api::FieldType>,
}

#[allow(clippy::trivially_copy_pass_by_ref, clippy::ref_option)]
fn serialize_field_type<S>(
    ty: &Option<rbw::api::FieldType>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match ty {
        Some(ty) => {
            let s = match ty {
                rbw::api::FieldType::Text => "text",
                rbw::api::FieldType::Hidden => "hidden",
                rbw::api::FieldType::Boolean => "boolean",
                rbw::api::FieldType::Linked => "linked",
            };
            serializer.serialize_some(&Some(s))
        }
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedHistoryEntry {
    last_used_date: String,
    password: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedUri {
    uri: String,
    match_type: Option<rbw::api::UriMatchType>,
}

fn matches_url(
    url: &str,
    match_type: Option<rbw::api::UriMatchType>,
    given_url: &url::Url,
) -> bool {
    match match_type.unwrap_or(rbw::api::UriMatchType::Domain) {
        rbw::api::UriMatchType::Domain => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && (self_host_port == given_host_port
                            || given_host_port
                                .ends_with(&format!(".{self_host_port}")))
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
                || given_host_port.ends_with(&format!(".{url}"))
        }
        rbw::api::UriMatchType::Host => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && self_host_port == given_host_port
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
        }
        rbw::api::UriMatchType::StartsWith => {
            given_url.to_string().starts_with(url)
        }
        rbw::api::UriMatchType::Exact => {
            if given_url.path() == "/" {
                given_url.to_string().trim_end_matches('/')
                    == url.trim_end_matches('/')
            } else {
                given_url.to_string() == url
            }
        }
        rbw::api::UriMatchType::RegularExpression => {
            let Ok(rx) = regex::Regex::new(url) else {
                return false;
            };
            rx.is_match(given_url.as_ref())
        }
        rbw::api::UriMatchType::Never => false,
    }
}

fn host_port(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(
        url.port().map_or_else(
            || host.to_string(),
            |port| format!("{host}:{port}"),
        ),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListField {
    Id,
    Name,
    User,
    Folder,
    Uri,
    EntryType,
}

impl ListField {
    fn all() -> Vec<Self> {
        vec![
            Self::Id,
            Self::Name,
            Self::User,
            Self::Folder,
            Self::Uri,
            Self::EntryType,
        ]
    }
}

impl std::convert::TryFrom<&String> for ListField {
    type Error = anyhow::Error;

    fn try_from(s: &String) -> anyhow::Result<Self> {
        Ok(match s.as_str() {
            "name" => Self::Name,
            "id" => Self::Id,
            "user" => Self::User,
            "folder" => Self::Folder,
            "type" => Self::EntryType,
            _ => return Err(anyhow::anyhow!("unknown field {s}")),
        })
    }
}

const HELP_PW: &str = r"
# The first line of this file will be the password, and the remainder of the
# file (after any blank lines after the password) will be stored as a note.
# Lines with leading # will be ignored.
";

const HELP_NOTES: &str = r"
# The content of this file will be stored as a note.
# Lines with leading # will be ignored.
";

pub fn config_show() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    serde_json::to_writer_pretty(std::io::stdout(), &config)
        .context("failed to write config to stdout")?;
    println!();

    Ok(())
}

pub fn config_set(key: &str, value: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = Some(value.to_string()),
        "sso_id" => config.sso_id = Some(value.to_string()),
        "base_url" => config.base_url = Some(value.to_string()),
        "identity_url" => config.identity_url = Some(value.to_string()),
        "ui_url" => config.ui_url = Some(value.to_string()),
        "notifications_url" => {
            config.notifications_url = Some(value.to_string());
        }
        "client_cert_path" => {
            config.client_cert_path =
                Some(std::path::PathBuf::from(value.to_string()));
        }
        "lock_timeout" => {
            let timeout = value
                .parse()
                .context("failed to parse value for lock_timeout")?;
            if timeout == 0 {
                log::error!("lock_timeout must be greater than 0");
            } else {
                config.lock_timeout = timeout;
            }
        }
        "sync_interval" => {
            let interval = value
                .parse()
                .context("failed to parse value for sync_interval")?;
            config.sync_interval = interval;
        }
        "pinentry" => config.pinentry = value.to_string(),
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}

pub fn config_unset(key: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = None,
        "sso_id" => config.sso_id = None,
        "base_url" => config.base_url = None,
        "identity_url" => config.identity_url = None,
        "ui_url" => config.ui_url = None,
        "notifications_url" => config.notifications_url = None,
        "client_cert_path" => config.client_cert_path = None,
        "lock_timeout" => {
            config.lock_timeout = rbw::config::default_lock_timeout();
        }
        "pinentry" => config.pinentry = rbw::config::default_pinentry(),
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}

pub fn register() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::register()?;

    Ok(())
}

pub fn login() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login(true)?;

    Ok(())
}

pub fn unlock() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login(false)?;
    crate::actions::unlock()?;

    Ok(())
}

pub fn unlocked() -> anyhow::Result<()> {
    // not ensure_agent, because we don't want `rbw unlocked` to start the
    // agent if it's not running
    let _ = check_agent_version();
    crate::actions::unlocked()?;

    Ok(())
}

pub fn sync() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login(false)?;
    crate::actions::sync()?;

    Ok(())
}

pub fn list(fields: &[String], raw: bool) -> anyhow::Result<()> {
    let fields: Vec<ListField> = if raw {
        ListField::all()
    } else {
        fields
            .iter()
            .map(std::convert::TryFrom::try_from)
            .collect::<anyhow::Result<_>>()?
    };

    unlock()?;

    let db = load_db()?;
    let mut entries: Vec<DecryptedListCipher> =
        batch_decrypt(&db.entries, |entry, decryptor| {
            decrypt_list_cipher(entry, &fields, decryptor)
        })?;
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    print_entry_list(&entries, &fields, raw)?;

    Ok(())
}

#[allow(clippy::fn_params_excessive_bools)]
pub fn get(
    needle: Needle,
    user: Option<&str>,
    folder: Option<&str>,
    field: Option<&str>,
    full: bool,
    raw: bool,
    clipboard: crate::clipboard::Mode,
    ignore_case: bool,
    list_fields: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let (_, decrypted) =
        find_entry(&db, needle, user, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    if list_fields {
        decrypted.display_fields_list();
    } else if raw {
        decrypted.display_json(&desc)?;
    } else if full {
        decrypted.display_long(&desc, clipboard, &Secrets::Show);
    } else if let Some(field) = field {
        decrypted.display_field(&desc, field, clipboard);
    } else {
        decrypted.display_short(&desc, clipboard);
    }

    Ok(())
}

fn print_entry_list(
    entries: &[DecryptedListCipher],
    fields: &[ListField],
    raw: bool,
) -> anyhow::Result<()> {
    if raw {
        serde_json::to_writer_pretty(std::io::stdout(), &entries)
            .context("failed to write entries to stdout".to_string())?;
        println!();
    } else {
        for entry in entries {
            let values: Vec<String> = fields
                .iter()
                .map(|field| match field {
                    ListField::Id => entry.id.clone(),
                    ListField::Name => entry.name.as_ref().map_or_else(
                        String::new,
                        std::string::ToString::to_string,
                    ),
                    ListField::User => entry.user.as_ref().map_or_else(
                        String::new,
                        std::string::ToString::to_string,
                    ),
                    ListField::Folder => entry.folder.as_ref().map_or_else(
                        String::new,
                        std::string::ToString::to_string,
                    ),
                    ListField::Uri => {
                        // "uri" is not listed in the TryFrom
                        // implementation, so there's no way to try to
                        // print it (and it's not clear what that would
                        // look like, since it's a list and not a single
                        // string)
                        unreachable!()
                    }
                    ListField::EntryType => {
                        entry.entry_type.as_ref().map_or_else(
                            String::new,
                            std::string::ToString::to_string,
                        )
                    }
                })
                .collect();

            // write to stdout but don't panic when pipe get's closed
            // this happens when piping stdout in a shell
            match writeln!(&mut std::io::stdout(), "{}", values.join("\t")) {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    Ok(())
                }
                res => res,
            }?;
        }
    }

    Ok(())
}

pub fn search(
    term: &str,
    fields: &[String],
    folder: Option<&str>,
    raw: bool,
) -> anyhow::Result<()> {
    let fields: Vec<ListField> = if raw {
        ListField::all()
    } else {
        fields
            .iter()
            .map(std::convert::TryFrom::try_from)
            .collect::<anyhow::Result<_>>()?
    };

    unlock()?;

    let db = load_db()?;

    let mut entries: Vec<DecryptedListCipher> =
        batch_decrypt(&db.entries, decrypt_search_cipher)?
            .into_iter()
            .filter(|entry| entry.search_match(term, folder))
            .map(std::convert::Into::into)
            .collect();
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    print_entry_list(&entries, &fields, raw)?;

    Ok(())
}

pub fn show(
    needle: Needle,
    user: Option<&str>,
    folder: Option<&str>,
    clipboard: crate::clipboard::Mode,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let needle_str = needle.to_string();
    let (_, decrypted) =
        find_entry(&db, needle, user, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    let copied = clipboard != crate::clipboard::Mode::Off
        && decrypted.display_short(&desc, clipboard);

    let mut entry_args = shell_quote(&needle_str);
    if let Some(user) = user {
        entry_args.push(' ');
        entry_args.push_str(&shell_quote(user));
    }
    if let Some(folder) = folder {
        entry_args.push_str(" --folder ");
        entry_args.push_str(&shell_quote(folder));
    }
    if ignore_case {
        entry_args.push_str(" -i");
    }
    decrypted.display_long(
        &desc,
        crate::clipboard::Mode::Off,
        &Secrets::Hide { entry_args, copied },
    );

    Ok(())
}

pub fn code(
    needle: Needle,
    user: Option<&str>,
    folder: Option<&str>,
    clipboard: crate::clipboard::Mode,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let (_, decrypted) =
        find_entry(&db, needle, user, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if let DecryptedData::Login { totp, .. } = decrypted.data {
        if let Some(totp) = totp {
            val_display_or_store(clipboard, &generate_totp(&totp)?);
        } else {
            return Err(anyhow::anyhow!(
                "entry does not contain a totp secret"
            ));
        }
    } else {
        return Err(anyhow::anyhow!("not a login entry"));
    }

    Ok(())
}

pub fn add(
    name: &str,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
) -> anyhow::Result<()> {
    unlock()?;

    let mut db = load_db()?;

    let name = crate::actions::encrypt(name, None)?;

    let username = username
        .map(|username| crate::actions::encrypt(username, None))
        .transpose()?;

    let contents = rbw::edit::edit("", HELP_PW, false)?;

    let (password, notes) = parse_editor(&contents);
    let password = password
        .map(|password| crate::actions::encrypt(&password, None))
        .transpose()?;
    let notes = notes
        .map(|notes| crate::actions::encrypt(&notes, None))
        .transpose()?;
    let uris: Vec<_> = uris
        .iter()
        .map(|uri| {
            Ok(rbw::db::Uri {
                uri: crate::actions::encrypt(&uri.0, None)?,
                match_type: uri.1,
            })
        })
        .collect::<anyhow::Result<_>>()?;

    let mut folder_id = None;
    if let Some(folder_name) = folder {
        let (access_token, refresh_token) = api_tokens(&db);
        let (tokens, folders) =
            rbw::actions::list_folders(access_token, refresh_token)?;
        store_tokens(&mut db, tokens)?;

        let folders: Vec<(String, String)> = folders
            .iter()
            .cloned()
            .map(|(id, name)| {
                Ok((id, crate::actions::decrypt(&name, None, None)?))
            })
            .collect::<anyhow::Result<_>>()?;

        for (id, name) in folders {
            if name == folder_name {
                folder_id = Some(id);
            }
        }
        if folder_id.is_none() {
            let (access_token, refresh_token) = api_tokens(&db);
            let (tokens, id) = rbw::actions::create_folder(
                access_token,
                refresh_token,
                &crate::actions::encrypt(folder_name, None)?,
            )?;
            store_tokens(&mut db, tokens)?;
            folder_id = Some(id);
        }
    }

    let (access_token, refresh_token) = api_tokens(&db);
    let (tokens, ()) = rbw::actions::add(
        access_token,
        refresh_token,
        &name,
        &rbw::db::EntryData::Login {
            username,
            password,
            uris,
            totp: None,
        },
        notes.as_deref(),
        folder_id.as_deref(),
    )?;
    store_tokens(&mut db, tokens)?;

    crate::actions::sync()?;

    Ok(())
}

pub fn generate(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    len: usize,
    ty: rbw::pwgen::Type,
) -> anyhow::Result<()> {
    let password = rbw::pwgen::pwgen(ty, len);
    println!("{password}");

    if let Some(name) = name {
        unlock()?;

        let mut db = load_db()?;

        let name = crate::actions::encrypt(name, None)?;
        let username = username
            .map(|username| crate::actions::encrypt(username, None))
            .transpose()?;
        let password = crate::actions::encrypt(&password, None)?;
        let uris: Vec<_> = uris
            .iter()
            .map(|uri| {
                Ok(rbw::db::Uri {
                    uri: crate::actions::encrypt(&uri.0, None)?,
                    match_type: uri.1,
                })
            })
            .collect::<anyhow::Result<_>>()?;

        let mut folder_id = None;
        if let Some(folder_name) = folder {
            let (access_token, refresh_token) = api_tokens(&db);
            let (tokens, folders) =
                rbw::actions::list_folders(access_token, refresh_token)?;
            store_tokens(&mut db, tokens)?;

            let folders: Vec<(String, String)> = folders
                .iter()
                .cloned()
                .map(|(id, name)| {
                    Ok((id, crate::actions::decrypt(&name, None, None)?))
                })
                .collect::<anyhow::Result<_>>()?;

            for (id, name) in folders {
                if name == folder_name {
                    folder_id = Some(id);
                }
            }
            if folder_id.is_none() {
                let (access_token, refresh_token) = api_tokens(&db);
                let (tokens, id) = rbw::actions::create_folder(
                    access_token,
                    refresh_token,
                    &crate::actions::encrypt(folder_name, None)?,
                )?;
                store_tokens(&mut db, tokens)?;
                folder_id = Some(id);
            }
        }

        let (access_token, refresh_token) = api_tokens(&db);
        let (tokens, ()) = rbw::actions::add(
            access_token,
            refresh_token,
            &name,
            &rbw::db::EntryData::Login {
                username,
                password: Some(password),
                uris,
                totp: None,
            },
            None,
            folder_id.as_deref(),
        )?;
        store_tokens(&mut db, tokens)?;

        crate::actions::sync()?;
    }

    Ok(())
}

pub fn edit(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let mut db = load_db()?;

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let entry = find_entry_undecrypted(
        &db.entries,
        name,
        username,
        folder,
        ignore_case,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    // edit the entry as the server currently has it, and only change the
    // values that were edited, so that everything else (including anything
    // rbw doesn't know about, like passkeys or attachments) is sent back
    // untouched
    let (access_token, refresh_token) = api_tokens(&db);
    let (tokens, mut cipher) =
        rbw::actions::get_cipher(access_token, refresh_token, &entry.id)?;
    store_tokens(&mut db, tokens)?;
    if !cipher.is_object() {
        return Err(anyhow::anyhow!("unexpected response from the server"));
    }

    let entry_key = cipher["key"].as_str().map(str::to_string);
    let org_id = cipher["organizationId"].as_str().map(str::to_string);
    let decrypt = |cipherstring: &serde_json::Value| {
        cipherstring
            .as_str()
            .map(|cipherstring| {
                crate::actions::decrypt(
                    cipherstring,
                    entry_key.as_deref(),
                    org_id.as_deref(),
                )
            })
            .transpose()
    };
    let encrypt = |plaintext: Option<String>| {
        plaintext.map_or(Ok(serde_json::Value::Null), |plaintext| {
            crate::actions::encrypt_with_key(
                &plaintext,
                entry_key.as_deref(),
                org_id.as_deref(),
            )
            .map(serde_json::Value::String)
        })
    };

    let old_notes = decrypt(&cipher["notes"])?;
    let new_notes = match cipher["type"].as_u64() {
        Some(1) => {
            let old_password = decrypt(&cipher["login"]["password"])?;
            let mut contents =
                format!("{}\n", old_password.as_deref().unwrap_or(""));
            if let Some(notes) = &old_notes {
                write!(contents, "\n{notes}\n").unwrap();
            }

            let contents = rbw::edit::edit(&contents, HELP_PW, true)?;
            let (new_password, new_notes) = parse_editor(&contents);

            if new_password != old_password {
                let old_password = cipher["login"]["password"].take();
                cipher["login"]["password"] = encrypt(new_password)?;
                if !old_password.is_null() {
                    let history = &mut cipher["passwordHistory"];
                    if !history.is_array() {
                        *history = serde_json::Value::Array(vec![]);
                    }
                    // unwrap is safe because of the check above
                    history.as_array_mut().unwrap().insert(
                        0,
                        serde_json::json!({
                            "lastUsedDate": jiff::Timestamp::now().to_string(),
                            "password": old_password,
                        }),
                    );
                }
            }
            new_notes
        }
        Some(2) => {
            let editor_content = old_notes.as_ref().map_or_else(
                || "\n".to_string(),
                |notes| format!("{notes}\n"),
            );
            let contents =
                rbw::edit::edit(&editor_content, HELP_NOTES, true)?;

            // prepend blank line to be parsed as pw by `parse_editor`
            let (_, notes) = parse_editor(&format!("\n{contents}\n"));
            notes
        }
        Some(_) => {
            return Err(anyhow::anyhow!(
                "modifications are only supported for login and note entries"
            ));
        }
        None => {
            return Err(anyhow::anyhow!(
                "failed to find the type of the entry in the server response"
            ));
        }
    };
    if new_notes != old_notes {
        cipher["notes"] = encrypt(new_notes)?;
    }

    // the server rejects the update if the entry was changed elsewhere since
    // it was fetched above
    if let Some(revision_date) = cipher.get("revisionDate").cloned() {
        cipher["lastKnownRevisionDate"] = revision_date;
    }
    // attachments are returned as a list, but updates take a map from id to
    // file name, and don't need it to keep the attachments
    if let Some(cipher) = cipher.as_object_mut() {
        cipher.remove("attachments");
    }

    let (access_token, refresh_token) = api_tokens(&db);
    let (tokens, ()) = rbw::actions::update_cipher(
        access_token,
        refresh_token,
        &entry.id,
        &cipher,
    )?;
    store_tokens(&mut db, tokens)?;

    crate::actions::sync()?;
    Ok(())
}

pub fn remove(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    permanent: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let mut db = load_db()?;

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    // entries can be deleted permanently from the trash as well
    let entries: Vec<rbw::db::Entry> = if permanent {
        db.entries.iter().chain(&db.trash).cloned().collect()
    } else {
        db.entries.clone()
    };
    let entry =
        find_entry_undecrypted(&entries, name, username, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let (access_token, refresh_token) = api_tokens(&db);
    let (tokens, ()) = if permanent {
        rbw::actions::remove(access_token, refresh_token, &entry.id)?
    } else {
        rbw::actions::trash(access_token, refresh_token, &entry.id)?
    };
    store_tokens(&mut db, tokens)?;

    crate::actions::sync()?;

    Ok(())
}

pub fn trash() -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;
    let mut names: Vec<String> =
        batch_decrypt(&db.trash, decrypt_search_cipher)?
            .iter()
            .map(DecryptedSearchCipher::display_name)
            .collect();
    names.sort_unstable();
    for name in names {
        println!("{name}");
    }

    Ok(())
}

pub fn restore(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let mut db = load_db()?;

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let entry = find_entry_undecrypted(
        &db.trash,
        name,
        username,
        folder,
        ignore_case,
    )
    .with_context(|| {
        format!("couldn't find entry for '{desc}' in the trash")
    })?;

    let (access_token, refresh_token) = api_tokens(&db);
    let (tokens, ()) =
        rbw::actions::restore(access_token, refresh_token, &entry.id)?;
    store_tokens(&mut db, tokens)?;

    crate::actions::sync()?;

    Ok(())
}

pub fn history(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let (_, decrypted) = find_entry(&db, name, username, folder, ignore_case)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    for history in decrypted.history {
        println!("{}: {}", history.last_used_date, history.password);
    }

    Ok(())
}

pub fn lock() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::lock()?;

    Ok(())
}

pub fn purge() -> anyhow::Result<()> {
    stop_agent()?;

    remove_db()?;

    Ok(())
}

pub fn stop_agent() -> anyhow::Result<()> {
    crate::actions::quit()?;

    Ok(())
}

fn ensure_agent() -> anyhow::Result<()> {
    check_config()?;
    if matches!(check_agent_version(), Ok(())) {
        return Ok(());
    }
    run_agent()?;
    check_agent_version()?;
    Ok(())
}

fn run_agent() -> anyhow::Result<()> {
    let agent_path = std::env::var_os("RBW_AGENT");
    let agent_path = agent_path
        .as_deref()
        .unwrap_or_else(|| std::ffi::OsStr::from_bytes(b"rbw-agent"));
    let status = std::process::Command::new(agent_path)
        .status()
        .context("failed to run rbw-agent")?;
    if !status.success() {
        if let Some(code) = status.code() {
            if code != 23 {
                return Err(anyhow::anyhow!(
                    "failed to run rbw-agent: {status}"
                ));
            }
        }
    }

    Ok(())
}

fn check_config() -> anyhow::Result<()> {
    rbw::config::Config::validate().map_err(|e| {
        log::error!("{MISSING_CONFIG_HELP}");
        anyhow::Error::new(e)
    })
}

fn check_agent_version() -> anyhow::Result<()> {
    let client_version = rbw::protocol::VERSION;
    let agent_version = version_or_quit()?;
    if agent_version != client_version {
        crate::actions::quit()?;
        return Err(anyhow::anyhow!(
            "client protocol version is {client_version} but agent protocol version is {agent_version}"
        ));
    }
    Ok(())
}

fn version_or_quit() -> anyhow::Result<u32> {
    crate::actions::version().inspect_err(|_| {
        let _ = crate::actions::quit();
    })
}

fn find_entry(
    db: &rbw::db::Db,
    needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedCipher)> {
    let entry = find_entry_undecrypted(
        &db.entries,
        needle,
        username,
        folder,
        ignore_case,
    )?;
    let decrypted_entry = decrypt_one(&entry)?;
    Ok((entry, decrypted_entry))
}

// like find_entry, but without decrypting the secrets of the entry
fn find_entry_undecrypted(
    entries: &[rbw::db::Entry],
    mut needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<rbw::db::Entry> {
    if let Needle::Uuid(uuid, s) = needle {
        for cipher in entries {
            if rbw::uuid::Uuid::parse(&cipher.id) == Some(uuid) {
                return Ok(cipher.clone());
            }
        }
        needle = Needle::Name(s);
    }

    let ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = entries
        .iter()
        .cloned()
        .zip(batch_decrypt(entries, decrypt_search_cipher)?)
        .collect();
    let (entry, _) =
        find_entry_raw(&ciphers, &needle, username, folder, ignore_case)?;
    Ok(entry)
}

fn find_entry_raw(
    entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
    needle: &Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
    let mut matches: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = vec![];

    let find_matches = |strict_username, strict_folder, exact| {
        entries
            .iter()
            .filter(|&(_, decrypted_cipher)| {
                decrypted_cipher.matches(
                    needle,
                    username,
                    folder,
                    ignore_case,
                    strict_username,
                    strict_folder,
                    exact,
                )
            })
            .cloned()
            .collect()
    };

    for exact in [true, false] {
        matches = find_matches(true, true, exact);
        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }

        let strict_folder_matches = find_matches(false, true, exact);
        let strict_username_matches = find_matches(true, false, exact);
        if strict_folder_matches.len() == 1
            && strict_username_matches.len() != 1
        {
            return Ok(strict_folder_matches[0].clone());
        } else if strict_folder_matches.len() != 1
            && strict_username_matches.len() == 1
        {
            return Ok(strict_username_matches[0].clone());
        }

        matches = find_matches(false, false, exact);
        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }
    }

    if matches.is_empty() {
        Err(anyhow::anyhow!("no entry found"))
    } else {
        let entries: Vec<String> = matches
            .iter()
            .map(|(_, decrypted)| decrypted.display_name())
            .collect();
        let entries = entries.join(", ");
        Err(anyhow::anyhow!("multiple entries found: {entries}"))
    }
}

// decrypting an entry takes one agent request per field, which adds up
// quickly when going through the whole vault (e.g. to find an entry by
// name). to avoid that, the decryption functions below go through a
// Decryptor, and are run twice: first to collect the cipherstrings they
// need, which are then decrypted with a single agent request, and then
// again with the results.
pub trait Decryptor {
    fn decrypt(
        &self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<String>;
}

type DecryptKey = (String, Option<String>, Option<String>);

fn decrypt_key(
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> DecryptKey {
    (
        cipherstring.to_string(),
        entry_key.map(str::to_string),
        org_id.map(str::to_string),
    )
}

// collects the cipherstrings, and returns placeholders for the plaintexts
#[derive(Default)]
struct CollectingDecryptor(
    std::cell::RefCell<std::collections::BTreeSet<DecryptKey>>,
);

impl Decryptor for CollectingDecryptor {
    fn decrypt(
        &self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        self.0.borrow_mut().insert(decrypt_key(
            cipherstring,
            entry_key,
            org_id,
        ));
        Ok(String::new())
    }
}

// returns the results of the batch request. results are looked up by their
// cipherstring rather than handed out in order, so if the decryption
// functions ever ask for something that wasn't collected, it is decrypted
// individually instead of returning the wrong value
struct BatchDecryptor(
    std::collections::HashMap<DecryptKey, Result<String, String>>,
);

impl Decryptor for BatchDecryptor {
    fn decrypt(
        &self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        match self.0.get(&decrypt_key(cipherstring, entry_key, org_id)) {
            Some(Ok(plaintext)) => Ok(plaintext.clone()),
            Some(Err(e)) => Err(anyhow::anyhow!("failed to decrypt: {e}")),
            None => crate::actions::decrypt(cipherstring, entry_key, org_id),
        }
    }
}

pub fn batch_decrypt<T>(
    entries: &[rbw::db::Entry],
    f: impl Fn(&rbw::db::Entry, &dyn Decryptor) -> anyhow::Result<T>,
) -> anyhow::Result<Vec<T>> {
    let collector = CollectingDecryptor::default();
    for entry in entries {
        // the plaintexts are only placeholders here, so the results (and
        // errors) are meaningless
        let _ = f(entry, &collector);
    }
    let keys: Vec<DecryptKey> =
        collector.0.into_inner().into_iter().collect();

    let results = if keys.is_empty() {
        vec![]
    } else {
        crate::actions::decrypt_many(
            keys.iter()
                .map(|(cipherstring, entry_key, org_id)| {
                    rbw::protocol::DecryptItem {
                        cipherstring: cipherstring.clone(),
                        entry_key: entry_key.clone(),
                        org_id: org_id.clone(),
                    }
                })
                .collect(),
        )?
    };
    if results.len() != keys.len() {
        return Err(anyhow::anyhow!(
            "agent returned {} decryption results for {} requests",
            results.len(),
            keys.len()
        ));
    }

    let decryptor = BatchDecryptor(keys.into_iter().zip(results).collect());
    entries.iter().map(|entry| f(entry, &decryptor)).collect()
}

fn decrypt_one(entry: &rbw::db::Entry) -> anyhow::Result<DecryptedCipher> {
    batch_decrypt(std::slice::from_ref(entry), decrypt_cipher)?
        .pop()
        .ok_or_else(|| anyhow::anyhow!("failed to decrypt entry"))
}

fn decrypt_field(
    name: Field,
    field: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    decryptor: &dyn Decryptor,
) -> Option<String> {
    let field = field
        .as_ref()
        .map(|field| decryptor.decrypt(field, entry_key, org_id))
        .transpose();
    match field {
        Ok(field) => field,
        Err(e) => {
            log::warn!("failed to decrypt {name}: {e}");
            None
        }
    }
}

fn decrypt_list_cipher(
    entry: &rbw::db::Entry,
    fields: &[ListField],
    decryptor: &dyn Decryptor,
) -> anyhow::Result<DecryptedListCipher> {
    let id = entry.id.clone();
    let name = if fields.contains(&ListField::Name) {
        Some(decryptor.decrypt(
            &entry.name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?)
    } else {
        None
    };
    let user = if fields.contains(&ListField::User) {
        match &entry.data {
            rbw::db::EntryData::Login { username, .. } => decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            _ => None,
        }
    } else {
        None
    };
    let folder = if fields.contains(&ListField::Folder) {
        // folder name should always be decrypted with the local key because
        // folders are local to a specific user's vault, not the organization
        entry
            .folder
            .as_ref()
            .map(|folder| decryptor.decrypt(folder, None, None))
            .transpose()?
    } else {
        None
    };
    let uris = if fields.contains(&ListField::Uri) {
        match &entry.data {
            rbw::db::EntryData::Login { uris, .. } => Some(
                uris.iter()
                    .filter_map(|s| {
                        decrypt_field(
                            Field::Uris,
                            Some(&s.uri),
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                            decryptor,
                        )
                    })
                    .collect(),
            ),
            _ => None,
        }
    } else {
        None
    };
    let entry_type = fields
        .contains(&ListField::EntryType)
        .then_some(match &entry.data {
            rbw::db::EntryData::Login { .. } => "Login",
            rbw::db::EntryData::Identity { .. } => "Identity",
            rbw::db::EntryData::SshKey { .. } => "SSH Key",
            rbw::db::EntryData::SecureNote => "Note",
            rbw::db::EntryData::Card { .. } => "Card",
        })
        .map(str::to_string);

    Ok(DecryptedListCipher {
        id,
        name,
        user,
        folder,
        uris,
        entry_type,
    })
}

fn decrypt_search_cipher(
    entry: &rbw::db::Entry,
    decryptor: &dyn Decryptor,
) -> anyhow::Result<DecryptedSearchCipher> {
    let id = entry.id.clone();
    let name = decryptor.decrypt(
        &entry.name,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let user = match &entry.data {
        rbw::db::EntryData::Login { username, .. } => decrypt_field(
            Field::Username,
            username.as_deref(),
            entry.key.as_deref(),
            entry.org_id.as_deref(),
            decryptor,
        ),
        _ => None,
    };
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| decryptor.decrypt(folder, None, None))
        .transpose()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            decryptor.decrypt(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose();
    let uris = if let rbw::db::EntryData::Login { uris, .. } = &entry.data {
        uris.iter()
            .filter_map(|s| {
                decrypt_field(
                    Field::Uris,
                    Some(&s.uri),
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                    decryptor,
                )
                .map(|uri| (uri, s.match_type))
            })
            .collect()
    } else {
        vec![]
    };
    let fields = entry
        .fields
        .iter()
        .filter_map(|field| {
            if field.ty == Some(rbw::api::FieldType::Hidden) {
                None
            } else {
                field.value.as_ref()
            }
        })
        .map(|value| {
            decryptor.decrypt(
                value,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .collect::<anyhow::Result<_>>()?;
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {e}");
            None
        }
    };
    let entry_type = (match &entry.data {
        rbw::db::EntryData::Login { .. } => "Login",
        rbw::db::EntryData::Identity { .. } => "Identity",
        rbw::db::EntryData::SshKey { .. } => "SSH Key",
        rbw::db::EntryData::SecureNote => "Note",
        rbw::db::EntryData::Card { .. } => "Card",
    })
    .to_string();

    Ok(DecryptedSearchCipher {
        id,
        entry_type,
        folder,
        name,
        user,
        uris,
        fields,
        notes,
    })
}

fn decrypt_cipher(
    entry: &rbw::db::Entry,
    decryptor: &dyn Decryptor,
) -> anyhow::Result<DecryptedCipher> {
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| decryptor.decrypt(folder, None, None))
        .transpose();
    let folder = match folder {
        Ok(folder) => folder,
        Err(e) => {
            log::warn!("failed to decrypt folder name: {e}");
            None
        }
    };
    let fields = entry
        .fields
        .iter()
        .map(|field| {
            Ok(DecryptedField {
                name: field
                    .name
                    .as_ref()
                    .map(|name| {
                        decryptor.decrypt(
                            name,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                value: field
                    .value
                    .as_ref()
                    .map(|value| {
                        decryptor.decrypt(
                            value,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                ty: field.ty,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            decryptor.decrypt(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose();
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {e}");
            None
        }
    };
    let history = entry
        .history
        .iter()
        .map(|history_entry| {
            Ok(DecryptedHistoryEntry {
                last_used_date: history_entry.last_used_date.clone(),
                password: decryptor.decrypt(
                    &history_entry.password,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )?,
            })
        })
        .collect::<anyhow::Result<_>>()?;

    let data = match &entry.data {
        rbw::db::EntryData::Login {
            username,
            password,
            totp,
            uris,
        } => DecryptedData::Login {
            username: decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            password: decrypt_field(
                Field::Password,
                password.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            totp: decrypt_field(
                Field::Totp,
                totp.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            uris: uris
                .iter()
                .map(|s| {
                    decrypt_field(
                        Field::Uris,
                        Some(&s.uri),
                        entry.key.as_deref(),
                        entry.org_id.as_deref(),
                        decryptor,
                    )
                    .map(|uri| DecryptedUri {
                        uri,
                        match_type: s.match_type,
                    })
                })
                .collect(),
        },
        rbw::db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DecryptedData::Card {
            cardholder_name: decrypt_field(
                Field::Cardholder,
                cardholder_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            number: decrypt_field(
                Field::CardNumber,
                number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            brand: decrypt_field(
                Field::Brand,
                brand.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            exp_month: decrypt_field(
                Field::ExpMonth,
                exp_month.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            exp_year: decrypt_field(
                Field::ExpYear,
                exp_year.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            code: decrypt_field(
                Field::Cvv,
                code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
        },
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
        } => DecryptedData::Identity {
            title: decrypt_field(
                Field::Title,
                title.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            first_name: decrypt_field(
                Field::FirstName,
                first_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            middle_name: decrypt_field(
                Field::MiddleName,
                middle_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            last_name: decrypt_field(
                Field::LastName,
                last_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            address1: decrypt_field(
                Field::Address1,
                address1.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            address2: decrypt_field(
                Field::Address2,
                address2.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            address3: decrypt_field(
                Field::Address3,
                address3.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            city: decrypt_field(
                Field::City,
                city.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            state: decrypt_field(
                Field::State,
                state.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            postal_code: decrypt_field(
                Field::PostalCode,
                postal_code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            country: decrypt_field(
                Field::Country,
                country.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            phone: decrypt_field(
                Field::Phone,
                phone.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            email: decrypt_field(
                Field::Email,
                email.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            ssn: decrypt_field(
                Field::Ssn,
                ssn.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            license_number: decrypt_field(
                Field::License,
                license_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            passport_number: decrypt_field(
                Field::Passport,
                passport_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            username: decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
        },
        rbw::db::EntryData::SecureNote => DecryptedData::SecureNote {},
        rbw::db::EntryData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => DecryptedData::SshKey {
            public_key: decrypt_field(
                Field::PublicKey,
                public_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            fingerprint: decrypt_field(
                Field::Fingerprint,
                fingerprint.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
            private_key: decrypt_field(
                Field::PrivateKey,
                private_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                decryptor,
            ),
        },
    };

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        folder,
        name: decryptor.decrypt(
            &entry.name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?,
        data,
        fields,
        notes,
        history,
    })
}

// unwrap is safe here because unlock() is guaranteed to populate these or
// error
fn api_tokens(db: &rbw::db::Db) -> (&str, &str) {
    (
        db.access_token.as_deref().unwrap(),
        db.refresh_token.as_deref().unwrap(),
    )
}

fn store_tokens(
    db: &mut rbw::db::Db,
    tokens: Option<rbw::actions::RefreshedTokens>,
) -> anyhow::Result<()> {
    if let Some(tokens) = tokens {
        tokens.store(db);
        save_db(db)?;
    }
    Ok(())
}

fn parse_editor(contents: &str) -> (Option<String>, Option<String>) {
    let mut lines = contents.lines();

    let password = lines.next().map(std::string::ToString::to_string);

    let mut notes: String = lines
        .skip_while(|line| line.is_empty())
        .filter(|line| !line.starts_with('#'))
        .fold(String::new(), |mut notes, line| {
            notes.push_str(line);
            notes.push('\n');
            notes
        });
    while notes.ends_with('\n') {
        notes.pop();
    }
    let notes = if notes.is_empty() { None } else { Some(notes) };

    (password, notes)
}

pub fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load()?;
    config.email.as_ref().map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        |email| {
            rbw::db::Db::load(&config.server_name(), email)
                .map_err(anyhow::Error::new)
        },
    )
}

fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    config.email.as_ref().map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        |email| {
            db.save(&config.server_name(), email)
                .map_err(anyhow::Error::new)
        },
    )
}

fn remove_db() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    config.email.as_ref().map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        |email| {
            rbw::db::Db::remove(&config.server_name(), email)
                .map_err(anyhow::Error::new)
        },
    )
}

struct TotpParams {
    secret: Vec<u8>,
    algorithm: String,
    digits: usize,
    period: u64,
}

fn decode_totp_secret(secret: &str) -> anyhow::Result<Vec<u8>> {
    let secret = secret.trim().replace(' ', "");
    decode_base32(&secret)
        .ok_or_else(|| anyhow::anyhow!("totp secret was not valid base32"))
}

// rfc 4648 base32, case insensitive, with optional padding
fn decode_base32(s: &str) -> Option<Vec<u8>> {
    let mut decoded = vec![];
    let mut buf = 0u16;
    let mut bits = 0;
    for c in s.trim_end_matches('=').bytes() {
        let value = match c.to_ascii_uppercase() {
            c @ b'A'..=b'Z' => c - b'A',
            c @ b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buf = (buf << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            decoded.push((buf >> bits).to_be_bytes()[1]);
        }
    }
    Some(decoded)
}

fn parse_totp_secret(secret: &str) -> anyhow::Result<TotpParams> {
    if let Ok(u) = url::Url::parse(secret) {
        match u.scheme() {
            "otpauth" => {
                if u.host_str() != Some("totp") {
                    return Err(anyhow::anyhow!(
                        "totp secret url must have totp host"
                    ));
                }

                let query: std::collections::HashMap<_, _> =
                    u.query_pairs().collect();

                let secret = decode_totp_secret(
                    query.get("secret").ok_or_else(|| {
                        anyhow::anyhow!("totp secret url must have secret")
                    })?,
                )?;
                let algorithm = query.get("algorithm").map_or_else(
                    || String::from("SHA1"),
                    std::string::ToString::to_string,
                );
                let digits = match query.get("digits") {
                    Some(dig) => dig
                        .parse::<usize>()
                        .map_err(|_| anyhow::anyhow!("digits parameter in totp url must be a valid integer."))?,
                    None => 6,
                };
                let period = match query.get("period") {
                    Some(dig) => {
                        dig.parse::<u64>().map_err(|_| anyhow::anyhow!("period parameter in totp url must be a valid integer."))?
                    }
                    None => TOTP_DEFAULT_STEP,
                };
                // steam codes always have the same length and period,
                // regardless of what the url says
                let (digits, period) = if algorithm == "STEAM" {
                    (5, TOTP_DEFAULT_STEP)
                } else {
                    (digits, period)
                };

                Ok(TotpParams {
                    secret,
                    algorithm,
                    digits,
                    period,
                })
            }
            "steam" => {
                let steam_secret = u.host_str().unwrap();

                Ok(TotpParams {
                    secret: decode_totp_secret(steam_secret)?,
                    algorithm: String::from("STEAM"),
                    digits: 5,
                    period: TOTP_DEFAULT_STEP,
                })
            }
            _ => Err(anyhow::anyhow!(
                "totp secret url must have 'otpauth' or 'steam' scheme"
            )),
        }
    } else {
        Ok(TotpParams {
            secret: decode_totp_secret(secret)?,
            algorithm: String::from("SHA1"),
            digits: 6,
            period: TOTP_DEFAULT_STEP,
        })
    }
}

// the current code, and the number of seconds it is still valid for
#[cfg(feature = "clipboard")]
pub fn totp_now(secret: &str) -> anyhow::Result<(String, u64)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let params = parse_totp_secret(secret)?;
    let code = totp_code(&params, now)?;
    Ok((code, params.period - now % params.period))
}

fn generate_totp(secret: &str) -> anyhow::Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    totp_code(&parse_totp_secret(secret)?, now)
}

// rfc 6238, plus the steam variant
fn totp_code(params: &TotpParams, time: u64) -> anyhow::Result<String> {
    const STEAM_CHARS: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

    if params.period == 0 {
        return Err(anyhow::anyhow!("totp period must be greater than zero"));
    }
    let counter = (time / params.period).to_be_bytes();
    let hash = match params.algorithm.as_str() {
        "SHA1" | "STEAM" => {
            totp_hmac::<hmac::Hmac<sha1::Sha1>>(&params.secret, &counter)
        }
        "SHA256" => {
            totp_hmac::<hmac::Hmac<sha2::Sha256>>(&params.secret, &counter)
        }
        "SHA512" => {
            totp_hmac::<hmac::Hmac<sha2::Sha512>>(&params.secret, &counter)
        }
        alg => {
            return Err(anyhow::anyhow!(
                "{alg} is not a valid totp algorithm"
            ))
        }
    };

    // dynamic truncation, rfc 4226 section 5.3
    let offset = usize::from(hash[hash.len() - 1] & 0xf);
    let mut code =
        u32::from_be_bytes(hash[offset..offset + 4].try_into().unwrap())
            & 0x7fff_ffff;

    if params.algorithm == "STEAM" {
        let base = u32::try_from(STEAM_CHARS.len()).unwrap();
        Ok((0..params.digits)
            .map(|_| {
                let c = STEAM_CHARS[usize::try_from(code % base).unwrap()];
                code /= base;
                char::from(c)
            })
            .collect())
    } else {
        let modulus = u32::try_from(params.digits)
            .ok()
            .filter(|digits| (1..=9).contains(digits))
            .map(|digits| 10u32.pow(digits))
            .ok_or_else(|| {
                anyhow::anyhow!("totp digits must be between 1 and 9")
            })?;
        Ok(format!("{:0width$}", code % modulus, width = params.digits))
    }
}

fn totp_hmac<M: hmac::Mac + hmac::digest::KeyInit>(
    key: &[u8],
    data: &[u8],
) -> Vec<u8> {
    // unwrap is safe because hmac accepts keys of any length
    let mut mac = <M as hmac::Mac>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn display_custom_field(
    field: &DecryptedField,
    clipboard: crate::clipboard::Mode,
    secrets: &Secrets,
) -> bool {
    let name = field.name.as_deref().unwrap_or("(null)");
    let value = field.value.as_deref().unwrap_or("");
    if matches!(secrets, Secrets::Hide { .. })
        && field.ty == Some(rbw::api::FieldType::Hidden)
    {
        secrets.display_hint(
            name,
            Some(value),
            "get",
            &format!(" -f {}", shell_quote(name)),
        )
    } else {
        display_field(name, Some(value), clipboard)
    }
}

fn display_field(
    name: &str,
    field: Option<&str>,
    clipboard: crate::clipboard::Mode,
) -> bool {
    field.map_or_else(
        || false,
        |field| val_display_or_store(clipboard, &format!("{name}: {field}")),
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_batch_decrypt() {
        // decrypts everything the collecting pass asked for by prefixing
        // it with "plain ", so the replay pass can be checked without an
        // agent
        fn run<T>(
            entry: &rbw::db::Entry,
            f: impl Fn(&rbw::db::Entry, &dyn Decryptor) -> anyhow::Result<T>,
        ) -> (Vec<String>, T) {
            let collector = CollectingDecryptor::default();
            f(entry, &collector).unwrap();
            let keys = collector.0.into_inner();
            let decryptor = BatchDecryptor(
                keys.iter()
                    .map(|key| (key.clone(), Ok(format!("plain {}", key.0))))
                    .collect(),
            );
            let cipherstrings = keys.into_iter().map(|key| key.0).collect();
            (cipherstrings, f(entry, &decryptor).unwrap())
        }

        let entry = rbw::db::Entry {
            id: "id".to_string(),
            org_id: Some("org".to_string()),
            folder: Some("folder".to_string()),
            folder_id: None,
            name: "name".to_string(),
            data: rbw::db::EntryData::Login {
                username: Some("username".to_string()),
                password: Some("password".to_string()),
                totp: Some("totp".to_string()),
                uris: vec![rbw::db::Uri {
                    uri: "uri".to_string(),
                    match_type: None,
                }],
            },
            fields: vec![
                rbw::db::Field {
                    ty: Some(rbw::api::FieldType::Text),
                    name: Some("text name".to_string()),
                    value: Some("text value".to_string()),
                    linked_id: None,
                },
                rbw::db::Field {
                    ty: Some(rbw::api::FieldType::Hidden),
                    name: Some("hidden name".to_string()),
                    value: Some("hidden value".to_string()),
                    linked_id: None,
                },
            ],
            notes: Some("notes".to_string()),
            history: vec![rbw::db::HistoryEntry {
                last_used_date: "2020-01-01".to_string(),
                password: "old password".to_string(),
            }],
            key: Some("entry key".to_string()),
            master_password_reprompt: rbw::api::CipherRepromptType::None,
        };

        let (cipherstrings, decrypted) = run(&entry, decrypt_cipher);
        assert_eq!(cipherstrings.len(), 12);
        assert_eq!(decrypted.name, "plain name");
        assert_eq!(decrypted.folder.as_deref(), Some("plain folder"));
        assert_eq!(decrypted.notes.as_deref(), Some("plain notes"));
        assert_eq!(decrypted.history[0].password, "plain old password");
        assert_eq!(
            decrypted.fields[1].value.as_deref(),
            Some("plain hidden value")
        );
        let DecryptedData::Login {
            username,
            password,
            totp,
            uris,
        } = decrypted.data
        else {
            panic!("not a login entry");
        };
        assert_eq!(username.as_deref(), Some("plain username"));
        assert_eq!(password.as_deref(), Some("plain password"));
        assert_eq!(totp.as_deref(), Some("plain totp"));
        assert_eq!(uris.unwrap()[0].uri, "plain uri");

        // searching must never decrypt secrets, since that could trigger
        // master password reprompts
        let (cipherstrings, decrypted) = run(&entry, decrypt_search_cipher);
        for secret in ["password", "totp", "hidden value", "old password"] {
            assert!(!cipherstrings.iter().any(|s| s == secret), "{secret}");
        }
        assert_eq!(decrypted.name, "plain name");
        assert_eq!(decrypted.user.as_deref(), Some("plain username"));
        assert_eq!(decrypted.notes.as_deref(), Some("plain notes"));

        let (_, decrypted) = run(&entry, |entry, decryptor| {
            decrypt_list_cipher(entry, &ListField::all(), decryptor)
        });
        assert_eq!(decrypted.name.as_deref(), Some("plain name"));
        assert_eq!(decrypted.user.as_deref(), Some("plain username"));
        assert_eq!(decrypted.folder.as_deref(), Some("plain folder"));
    }

    #[test]
    fn test_shell_quote() {
        assert_eq!(shell_quote("github"), "github");
        assert_eq!(shell_quote("https://x.org/a"), "https://x.org/a");
        assert_eq!(shell_quote("foo bar"), "'foo bar'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("$HOME"), "'$HOME'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn test_find_entry() {
        let entries = &[
            make_entry("github", Some("foo"), None, &[]),
            make_entry("gitlab", Some("foo"), None, &[]),
            make_entry("gitlab", Some("bar"), None, &[]),
            make_entry("gitter", Some("baz"), None, &[]),
            make_entry("git", Some("foo"), None, &[]),
            make_entry("bitwarden", None, None, &[]),
            make_entry("github", Some("foo"), Some("websites"), &[]),
            make_entry("github", Some("foo"), Some("ssh"), &[]),
            make_entry("github", Some("root"), Some("ssh"), &[]),
            make_entry("codeberg", Some("foo"), None, &[]),
            make_entry("codeberg", None, None, &[]),
            make_entry("1password", Some("foo"), None, &[]),
            make_entry("1password", None, Some("foo"), &[]),
        ];

        assert!(
            one_match(entries, "github", Some("foo"), None, 0, false),
            "foo@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("foo"), None, 0, true),
            "foo@GITHUB"
        );
        assert!(one_match(entries, "github", None, None, 0, false), "github");
        assert!(one_match(entries, "GITHUB", None, None, 0, true), "GITHUB");
        assert!(
            one_match(entries, "gitlab", Some("foo"), None, 1, false),
            "foo@gitlab"
        );
        assert!(
            one_match(entries, "GITLAB", Some("foo"), None, 1, true),
            "foo@GITLAB"
        );
        assert!(
            one_match(entries, "git", Some("bar"), None, 2, false),
            "bar@git"
        );
        assert!(
            one_match(entries, "GIT", Some("bar"), None, 2, true),
            "bar@GIT"
        );
        assert!(
            one_match(entries, "gitter", Some("ba"), None, 3, false),
            "ba@gitter"
        );
        assert!(
            one_match(entries, "GITTER", Some("ba"), None, 3, true),
            "ba@GITTER"
        );
        assert!(
            one_match(entries, "git", Some("foo"), None, 4, false),
            "foo@git"
        );
        assert!(
            one_match(entries, "GIT", Some("foo"), None, 4, true),
            "foo@GIT"
        );
        assert!(one_match(entries, "git", None, None, 4, false), "git");
        assert!(one_match(entries, "GIT", None, None, 4, true), "GIT");
        assert!(
            one_match(entries, "bitwarden", None, None, 5, false),
            "bitwarden"
        );
        assert!(
            one_match(entries, "BITWARDEN", None, None, 5, true),
            "BITWARDEN"
        );
        assert!(
            one_match(
                entries,
                "github",
                Some("foo"),
                Some("websites"),
                6,
                false
            ),
            "websites/foo@github"
        );
        assert!(
            one_match(
                entries,
                "GITHUB",
                Some("foo"),
                Some("websites"),
                6,
                true
            ),
            "websites/foo@GITHUB"
        );
        assert!(
            one_match(entries, "github", Some("foo"), Some("ssh"), 7, false),
            "ssh/foo@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("foo"), Some("ssh"), 7, true),
            "ssh/foo@GITHUB"
        );
        assert!(
            one_match(entries, "github", Some("root"), None, 8, false),
            "ssh/root@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("root"), None, 8, true),
            "ssh/root@GITHUB"
        );

        assert!(
            no_matches(entries, "gitlab", Some("baz"), None, false),
            "baz@gitlab"
        );
        assert!(
            no_matches(entries, "GITLAB", Some("baz"), None, true),
            "baz@"
        );
        assert!(
            no_matches(entries, "bitbucket", Some("foo"), None, false),
            "foo@bitbucket"
        );
        assert!(
            no_matches(entries, "BITBUCKET", Some("foo"), None, true),
            "foo@BITBUCKET"
        );
        assert!(
            no_matches(entries, "github", Some("foo"), Some("bar"), false),
            "bar/foo@github"
        );
        assert!(
            no_matches(entries, "GITHUB", Some("foo"), Some("bar"), true),
            "bar/foo@"
        );
        assert!(
            no_matches(entries, "gitlab", Some("foo"), Some("bar"), false),
            "bar/foo@gitlab"
        );
        assert!(
            no_matches(entries, "GITLAB", Some("foo"), Some("bar"), true),
            "bar/foo@GITLAB"
        );

        assert!(many_matches(entries, "gitlab", None, None, false), "gitlab");
        assert!(many_matches(entries, "gitlab", None, None, true), "GITLAB");
        assert!(
            many_matches(entries, "gi", Some("foo"), None, false),
            "foo@gi"
        );
        assert!(
            many_matches(entries, "GI", Some("foo"), None, true),
            "foo@GI"
        );
        assert!(
            many_matches(entries, "git", Some("ba"), None, false),
            "ba@git"
        );
        assert!(
            many_matches(entries, "GIT", Some("ba"), None, true),
            "ba@GIT"
        );
        assert!(
            many_matches(entries, "github", Some("foo"), Some("s"), false),
            "s/foo@github"
        );
        assert!(
            many_matches(entries, "GITHUB", Some("foo"), Some("s"), true),
            "s/foo@GITHUB"
        );

        assert!(
            one_match(entries, "codeberg", Some("foo"), None, 9, false),
            "foo@codeberg"
        );
        assert!(
            one_match(entries, "codeberg", None, None, 10, false),
            "codeberg"
        );
        assert!(
            no_matches(entries, "codeberg", Some("bar"), None, false),
            "bar@codeberg"
        );

        assert!(
            many_matches(entries, "1password", None, None, false),
            "1password"
        );
    }

    #[test]
    fn test_find_by_uuid() {
        let entries = &[
            make_entry("github", Some("foo"), None, &[]),
            make_entry("gitlab", Some("foo"), None, &[]),
            make_entry("gitlab", Some("bar"), None, &[]),
            make_entry(
                "12345678-1234-1234-1234-1234567890ab",
                None,
                None,
                &[],
            ),
            make_entry(
                "12345678-1234-1234-1234-1234567890AC",
                None,
                None,
                &[],
            ),
            make_entry("123456781234123412341234567890AD", None, None, &[]),
        ];

        assert!(
            one_match(entries, &entries[0].0.id, None, None, 0, false),
            "foo@github"
        );
        assert!(
            one_match(entries, &entries[1].0.id, None, None, 1, false),
            "foo@gitlab"
        );
        assert!(
            one_match(entries, &entries[2].0.id, None, None, 2, false),
            "bar@gitlab"
        );

        assert!(
            one_match(
                entries,
                &entries[0].0.id.to_uppercase(),
                None,
                None,
                0,
                false
            ),
            "foo@github"
        );
        assert!(
            one_match(
                entries,
                &entries[0].0.id.to_lowercase(),
                None,
                None,
                0,
                false
            ),
            "foo@github"
        );

        assert!(one_match(entries, &entries[3].0.id, None, None, 3, false));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890ab",
            None,
            None,
            3,
            false
        ));
        assert!(no_matches(
            entries,
            "12345678-1234-1234-1234-1234567890AB",
            None,
            None,
            false
        ));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890AB",
            None,
            None,
            3,
            true
        ));
        assert!(one_match(entries, &entries[4].0.id, None, None, 4, false));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890AC",
            None,
            None,
            4,
            false
        ));
        assert!(one_match(entries, &entries[5].0.id, None, None, 5, false));
        assert!(one_match(
            entries,
            "123456781234123412341234567890AD",
            None,
            None,
            5,
            false
        ));
    }

    #[test]
    fn test_find_by_url_default() {
        let entries = &[
            make_entry("one", None, None, &[("https://one.com/", None)]),
            make_entry("two", None, None, &[("https://two.com/login", None)]),
            make_entry(
                "three",
                None,
                None,
                &[("https://login.three.com/", None)],
            ),
            make_entry("four", None, None, &[("four.com", None)]),
            make_entry(
                "five",
                None,
                None,
                &[("https://five.com:8080/", None)],
            ),
            make_entry("six", None, None, &[("six.com:8080", None)]),
            make_entry("seven", None, None, &[("192.168.0.128:8080", None)]),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(
                entries,
                "https://login.one.com/",
                None,
                None,
                0,
                false
            ),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_domain() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "seven",
                None,
                None,
                &[(
                    "192.168.0.128:8080",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(
                entries,
                "https://login.one.com/",
                None,
                None,
                0,
                false
            ),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_host() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "seven",
                None,
                None,
                &[("192.168.0.128:8080", Some(rbw::api::UriMatchType::Host))],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_starts_with() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[(
                    "https://one.com/",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                1,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );
    }

    #[test]
    fn test_find_by_url_exact() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Exact))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Exact),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Exact),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("https://four.com", Some(rbw::api::UriMatchType::Exact))],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://one.com/foo", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );
        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );
        assert!(
            one_match(entries, "https://four.com", None, None, 3, false),
            "four"
        );
        assert!(
            no_matches(entries, "https://four.com/foo", None, None, false),
            "four"
        );
    }

    #[test]
    fn test_find_by_url_regex() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[(
                    r"^https://one\.com/$",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    r"^https://two\.com/(login|start)",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    r"^https://(login\.)?three\.com/$",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(entries, "https://two.com/start", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                1,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            one_match(entries, "https://three.com/", None, None, 2, false),
            "three"
        );
        assert!(
            no_matches(entries, "https://www.three.com/", None, None, false),
            "three"
        );
    }

    #[test]
    fn test_find_by_url_never() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Never))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Never))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Never))],
            ),
        ];

        assert!(
            no_matches(entries, "https://one.com/", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://one.com:443/", None, None, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            no_matches(
                entries,
                "https://login.three.com/",
                None,
                None,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            no_matches(entries, "https://four.com/", None, None, false),
            "four"
        );

        assert!(
            no_matches(entries, "https://five.com:8080/", None, None, false),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            no_matches(entries, "https://six.com:8080/", None, None, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
    }

    #[test]
    fn test_find_with_multiple_urls() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[
                    (
                        "https://one.com/",
                        Some(rbw::api::UriMatchType::Domain),
                    ),
                    (
                        "https://two.com/",
                        Some(rbw::api::UriMatchType::Domain),
                    ),
                ],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
        ];

        assert!(
            no_matches(entries, "https://zero.com/", None, None, false),
            "zero"
        );
        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            many_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
    }

    #[test]
    fn test_decode_totp_secret() {
        let decoded = decode_totp_secret("NBSW Y3DP EB3W 64TM MQQQ").unwrap();
        let want = b"hello world!".to_vec();
        assert!(decoded == want, "strips spaces");
    }

    #[track_caller]
    fn one_match(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        idx: usize,
        ignore_case: bool,
    ) -> bool {
        entries_eq(
            &find_entry_raw(
                entries,
                &parse_needle(needle).unwrap(),
                username,
                folder,
                ignore_case,
            )
            .unwrap(),
            &entries[idx],
        )
    }

    #[track_caller]
    fn no_matches(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
    ) -> bool {
        let res = find_entry_raw(
            entries,
            &parse_needle(needle).unwrap(),
            username,
            folder,
            ignore_case,
        );
        if let Err(e) = res {
            format!("{e}").contains("no entry found")
        } else {
            false
        }
    }

    #[track_caller]
    fn many_matches(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
    ) -> bool {
        let res = find_entry_raw(
            entries,
            &parse_needle(needle).unwrap(),
            username,
            folder,
            ignore_case,
        );
        if let Err(e) = res {
            format!("{e}").contains("multiple entries found")
        } else {
            false
        }
    }

    #[track_caller]
    fn entries_eq(
        a: &(rbw::db::Entry, DecryptedSearchCipher),
        b: &(rbw::db::Entry, DecryptedSearchCipher),
    ) -> bool {
        a.0 == b.0 && a.1 == b.1
    }

    fn make_entry(
        name: &str,
        username: Option<&str>,
        folder: Option<&str>,
        uris: &[(&str, Option<rbw::api::UriMatchType>)],
    ) -> (rbw::db::Entry, DecryptedSearchCipher) {
        let id = rbw::uuid::Uuid::new_v4();
        (
            rbw::db::Entry {
                id: id.to_string(),
                org_id: None,
                folder: folder.map(|_| "encrypted folder name".to_string()),
                folder_id: None,
                name: "this is the encrypted name".to_string(),
                data: rbw::db::EntryData::Login {
                    username: username.map(|_| {
                        "this is the encrypted username".to_string()
                    }),
                    password: None,
                    uris: uris
                        .iter()
                        .map(|(_, match_type)| rbw::db::Uri {
                            uri: "this is the encrypted uri".to_string(),
                            match_type: *match_type,
                        })
                        .collect(),
                    totp: None,
                },
                fields: vec![],
                notes: None,
                history: vec![],
                key: None,
                master_password_reprompt: rbw::api::CipherRepromptType::None,
            },
            DecryptedSearchCipher {
                id: id.to_string(),
                entry_type: "Login".to_string(),
                folder: folder.map(std::string::ToString::to_string),
                name: name.to_string(),
                user: username.map(std::string::ToString::to_string),
                uris: uris
                    .iter()
                    .map(|(uri, match_type)| {
                        ((*uri).to_string(), *match_type)
                    })
                    .collect(),
                fields: vec![],
                notes: None,
            },
        )
    }
    #[test]
    fn test_totp() {
        // test vectors from rfc 6238 appendix b
        let secrets = [
            ("SHA1", &b"12345678901234567890"[..]),
            ("SHA256", &b"12345678901234567890123456789012"[..]),
            (
                "SHA512",
                &b"1234567890123456789012345678901234567890123456789012345678901234"[..],
            ),
        ];
        let vectors: &[(u64, [&str; 3])] = &[
            (59, ["94287082", "46119246", "90693936"]),
            (1_111_111_109, ["07081804", "68084774", "25091201"]),
            (1_111_111_111, ["14050471", "67062674", "99943326"]),
            (1_234_567_890, ["89005924", "91819424", "93441116"]),
            (2_000_000_000, ["69279037", "90698825", "38618901"]),
            (20_000_000_000, ["65353130", "77737706", "47863826"]),
        ];
        for (time, codes) in vectors {
            for ((algorithm, secret), code) in secrets.iter().zip(codes) {
                let params = TotpParams {
                    secret: secret.to_vec(),
                    algorithm: (*algorithm).to_string(),
                    digits: 8,
                    period: 30,
                };
                assert_eq!(totp_code(&params, *time).unwrap(), *code);
            }
        }

        let params = TotpParams {
            secret: b"12345678901234567890".to_vec(),
            algorithm: "STEAM".to_string(),
            digits: 5,
            period: 30,
        };
        assert_eq!(totp_code(&params, 1_111_111_109).unwrap(), "PY4YB");

        let params = parse_totp_secret(
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=STEAM",
        )
        .unwrap();
        assert_eq!(params.digits, 5);
        assert_eq!(params.period, 30);
        assert_eq!(totp_code(&params, 1_111_111_109).unwrap(), "PY4YB");

        let mut params = TotpParams {
            secret: vec![],
            algorithm: "SHA1".to_string(),
            digits: 10,
            period: 30,
        };
        assert!(totp_code(&params, 0).is_err());
        params.digits = 6;
        params.period = 0;
        assert!(totp_code(&params, 0).is_err());
    }

    #[test]
    fn test_decode_base32() {
        assert_eq!(decode_base32("").unwrap(), b"");
        assert_eq!(decode_base32("MY======").unwrap(), b"f");
        assert_eq!(decode_base32("MZXW6YQ=").unwrap(), b"foob");
        assert_eq!(decode_base32("MZXW6YTBOI").unwrap(), b"foobar");
        assert_eq!(decode_base32("mzxw6ytboi======").unwrap(), b"foobar");
        assert_eq!(decode_base32("MzXw6yTbOi").unwrap(), b"foobar");
        assert!(decode_base32("MZXW6YTBO1").is_none());
        assert!(decode_base32("MZ=W6YTBOI").is_none());
    }
}
