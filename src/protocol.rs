use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

pub const VERSION: u32 = {
    const fn unwrap(res: &Result<u32, std::num::ParseIntError>) -> u32 {
        match res {
            Ok(t) => *t,
            Err(_) => panic!("failed to parse cargo version"),
        }
    }

    let major = env!("CARGO_PKG_VERSION_MAJOR");
    let minor = env!("CARGO_PKG_VERSION_MINOR");
    let patch = env!("CARGO_PKG_VERSION_PATCH");

    unwrap(&u32::from_str_radix(major, 10)) * 1_000_000
        + unwrap(&u32::from_str_radix(minor, 10)) * 1_000
        + unwrap(&u32::from_str_radix(patch, 10))
};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Request {
    tty: Option<String>,
    environment: Option<Environment>,
    action: Action,
}

impl Request {
    pub fn new(environment: Environment, action: Action) -> Self {
        Self {
            tty: None,
            environment: Some(environment),
            action,
        }
    }

    pub fn into_parts(self) -> (Action, Environment) {
        (
            self.action,
            self.environment.unwrap_or_else(|| Environment {
                tty: self.tty.map(|tty| SerializableOsString(tty.into())),
                env_vars: vec![],
            }),
        )
    }
}

// Taken from https://github.com/gpg/gnupg/blob/36dbca3e6944d13e75e96eace634e58a7d7e201d/common/session-env.c#L62-L91
pub const ENVIRONMENT_VARIABLES: &[&str] = &[
    // Used to set ttytype
    "TERM",
    // The X display
    "DISPLAY",
    // Xlib Authentication
    "XAUTHORITY",
    // Used by Xlib to select X input modules (e.g. "@im=SCIM")
    "XMODIFIERS",
    // For the Wayland display engine.
    "WAYLAND_DISPLAY",
    // Used by Qt and other non-GTK toolkits to check for X11 or Wayland
    "XDG_SESSION_TYPE",
    // Used by Qt to explicitly request X11 or Wayland; in particular, needed to
    // make Qt use Wayland on GNOME
    "QT_QPA_PLATFORM",
    // Used by GTK to select GTK input modules (e.g. "scim-bridge")
    "GTK_IM_MODULE",
    // Used by GNOME 3 to talk to gcr over dbus
    "DBUS_SESSION_BUS_ADDRESS",
    // Used by Qt to select Qt input modules (e.g. "xim")
    "QT_IM_MODULE",
    // Used for communication with non-standard Pinentries
    "PINENTRY_USER_DATA",
    // Used to pass window information
    "PINENTRY_GEOM_HINT",
];

pub static ENVIRONMENT_VARIABLES_OS: std::sync::LazyLock<
    Vec<std::ffi::OsString>,
> = std::sync::LazyLock::new(|| {
    ENVIRONMENT_VARIABLES
        .iter()
        .map(std::ffi::OsString::from)
        .collect()
});

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
struct SerializableOsString(std::ffi::OsString);

impl serde::Serialize for SerializableOsString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&crate::base64::encode(self.0.as_bytes()))
    }
}

impl<'de> serde::Deserialize<'de> for SerializableOsString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = SerializableOsString;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("base64 encoded os string")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SerializableOsString(std::ffi::OsString::from_vec(
                    crate::base64::decode(s).map_err(|_| {
                        E::invalid_value(serde::de::Unexpected::Str(s), &self)
                    })?,
                )))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct Environment {
    tty: Option<SerializableOsString>,
    env_vars: Vec<(SerializableOsString, SerializableOsString)>,
}

impl Environment {
    // the relevant environment variables of the current process
    pub fn from_process(tty: Option<std::ffi::OsString>) -> Self {
        let env_vars = std::env::vars_os()
            .filter(|(var, _)| (*ENVIRONMENT_VARIABLES_OS).contains(var))
            .collect();
        let over_ssh = std::env::var_os("SSH_CONNECTION")
            .is_some_and(|val| !val.is_empty());
        Self::new(tty, drop_session_bus_over_ssh(env_vars, over_ssh))
    }

    pub fn new(
        tty: Option<std::ffi::OsString>,
        env_vars: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    ) -> Self {
        Self {
            tty: tty.map(SerializableOsString),
            env_vars: env_vars
                .into_iter()
                .map(|(k, v)| {
                    (SerializableOsString(k), SerializableOsString(v))
                })
                .collect(),
        }
    }

    pub fn tty(&self) -> Option<&std::ffi::OsStr> {
        self.tty.as_ref().map(|tty| tty.0.as_os_str())
    }

    pub fn env_vars(
        &self,
    ) -> std::collections::HashMap<std::ffi::OsString, std::ffi::OsString>
    {
        self.env_vars
            .iter()
            .map(|(var, val)| (var.0.clone(), val.0.clone()))
            .filter(|(var, _)| (*ENVIRONMENT_VARIABLES_OS).contains(var))
            // an empty value (e.g. from `DBUS_SESSION_BUS_ADDRESS= rbw ...`)
            // is meant as unset, but pinentry would still see the variable
            // as present
            .filter(|(_, val)| !val.is_empty())
            .collect()
    }
}

// over ssh, pinentry-gnome3 would prompt on the remote machine's desktop via
// the session bus, even with a forwarded display; without it, it uses the tty
fn drop_session_bus_over_ssh(
    mut env_vars: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    over_ssh: bool,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    if over_ssh {
        env_vars.retain(|(var, _)| var != "DBUS_SESSION_BUS_ADDRESS");
    }
    env_vars
}

#[test]
fn test_drop_session_bus_over_ssh() {
    let vars = |vars: &[(&str, &str)]| -> Vec<_> {
        vars.iter().map(|(k, v)| (k.into(), v.into())).collect()
    };
    let bus = ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus");
    let term = ("TERM", "xterm");

    assert_eq!(
        drop_session_bus_over_ssh(vars(&[bus, term]), true),
        vars(&[term])
    );
    assert_eq!(
        drop_session_bus_over_ssh(vars(&[bus, ("DISPLAY", "")]), true),
        vars(&[("DISPLAY", "")])
    );
    assert_eq!(
        drop_session_bus_over_ssh(vars(&[bus, term]), false),
        vars(&[bus, term])
    );
    assert_eq!(
        drop_session_bus_over_ssh(
            vars(&[bus, ("DISPLAY", "localhost:10.0")]),
            true
        ),
        vars(&[("DISPLAY", "localhost:10.0")])
    );
    assert_eq!(
        drop_session_bus_over_ssh(
            vars(&[bus, ("WAYLAND_DISPLAY", "wayland-0")]),
            true
        ),
        vars(&[("WAYLAND_DISPLAY", "wayland-0")])
    );
}

#[test]
fn test_env_vars_skip_empty() {
    let env = Environment::new(
        None,
        vec![
            ("DISPLAY".into(), "".into()),
            ("DBUS_SESSION_BUS_ADDRESS".into(), "".into()),
            ("TERM".into(), "xterm".into()),
        ],
    );
    assert_eq!(
        env.env_vars(),
        std::collections::HashMap::from([("TERM".into(), "xterm".into())])
    );
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Action {
    // explicit is set for `rbw login` itself (as opposed to the implicit
    // login before other commands), which also logs in again if the server
    // rejected the stored refresh token
    Login {
        explicit: bool,
    },
    Register,
    Unlock,
    CheckLock,
    Lock,
    Sync,
    Decrypt {
        cipherstring: String,
        entry_key: Option<String>,
        org_id: Option<String>,
    },
    // decrypts many cipherstrings with a single request. failures are
    // reported for each item individually.
    DecryptMany {
        items: Vec<DecryptItem>,
    },
    Encrypt {
        plaintext: String,
        entry_key: Option<String>,
        org_id: Option<String>,
    },
    Quit,
    Version,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct DecryptItem {
    pub cipherstring: String,
    pub entry_key: Option<String>,
    pub org_id: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Response {
    Ack,
    Error {
        error: String,
    },
    Decrypt {
        plaintext: String,
    },
    DecryptMany {
        plaintexts: Vec<Result<String, String>>,
    },
    Encrypt {
        cipherstring: String,
    },
    Version {
        version: u32,
    },
}
