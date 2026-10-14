#![allow(clippy::all, dead_code, non_camel_case_types)]

pub mod securemessage {
    include!(concat!(env!("OUT_DIR"), "/securemessage.rs"));
}

pub mod securegcm {
    include!(concat!(env!("OUT_DIR"), "/securegcm.rs"));
}

pub mod location {
    pub mod nearby {
        pub mod connections {
            include!(concat!(
                env!("OUT_DIR"),
                "/location.nearby.connections.rs"
            ));
        }
        pub mod proto {
            pub mod sharing {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/location.nearby.proto.sharing.rs"
                ));
            }
        }
    }
}

pub mod nearby {
    pub mod sharing {
        pub mod service {
            pub mod proto {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/nearby.sharing.service.proto.rs"
                ));
            }
        }
    }
}

pub mod pbvalueset {
    include!(concat!(env!("OUT_DIR"), "/pbvalueset.rs"));
}

pub mod platform_sdk {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/platform_sdk.v1.rs"));
    }
}

pub mod side_channel {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/side_channel.v1.rs"));
    }
}

pub mod file_transfer {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/file_transfer.v1.rs"));
    }
}

pub mod fre {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/fre.v1.rs"));
    }
}
