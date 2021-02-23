use pam_client;
use std::io;
use nix::unistd;
use std::mem;
use std::path::Path;
use std::ffi::OsString;
use libc;
use std::process::Command;
use std::process::ExitStatus;
use std::os::unix::process::CommandExt;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;


#[derive(Debug, Clone)]
struct DesktopSession {
    pub id: String,
    pub name: String,
    pub argv: Vec<String>,
    pub typ: &'static str,
}

impl DesktopSession {
    pub fn load(path: &Path) -> io::Result<Self>{
        use io::ErrorKind::Other;
        use ini::Error::{Io, Parse};

        let desktopentry = ini::Ini::load_from_file(path)
            .map_err(|e| match e {Io(ie) => ie, Parse(pe)=>io::Error::new(Other, Box::new(pe))})?;
        let s = desktopentry.section(Some("Desktop Entry"))
            .ok_or(io::Error::new(Other, "no section 'Desktop Entry'"))?;
        let name = s.get("Name")
            .ok_or(io::Error::new(Other, "no entry Name"))?
            .to_owned();
        let argv = s.get("Exec")
            .ok_or(io::Error::new(Other, "no entry Exec"))?
            .split_whitespace().map(&str::to_owned).collect::<Vec<_>>();
        let id = path.file_name().unwrap().to_str().unwrap().to_owned();
        Ok(DesktopSession{id, name, argv, typ: &"tty"})
    }

    pub fn discover() -> Vec<Self> {
        let datadirs_string = std::env::var("XDG_DATA_DIRS").unwrap_or_else(|_| "/usr/local/share:/usr/share".to_owned());
        let sessiondirs = &["wayland-sessions", "xsessions"];
        
        let mut res = Vec::with_capacity(8);
        for dd in datadirs_string.split(':') {
            for sd in sessiondirs {
                let p = Path::new(dd).join(sd);
                let r = std::fs::read_dir(Path::new(dd).join(sd));
                match r {
                    Err(_) => {}
                    Ok(rd) => {
                        for file in rd {
                            if let Ok(file) = file {
                                match Self::load(&file.path()){
                                    Ok(mut s) => {
                                        if sd == &"wayland-sessions" {
                                            s.typ = &"wayland";
                                        }
                                        else if sd == &"xsessions" {
                                            s.typ = "x11";
                                        }
                                        res.push(s); }
                                    Err(e) => { println!("Error: {:?}", e); }
                                }
                            }
                        }
                    }
                }
            }
        }
        res
    }
}


fn main() -> io::Result<()>{
    let mut pamh_greeter = pam_client::Context::new("textdm-greeter", Some("root"), pam_client::conv_null::Conversation::new()).expect("creating greeter context failed");
    pamh_greeter.putenv("XDG_SESSION_CLASS=greeter").expect("putenv for session class failed");
    let ttypath = unistd::ttyname(0).expect("not on tty!");
    let ttyname = ttypath.to_str().expect("tty path not UTF8 :/");
    println!("My TTY is {:?}", ttyname);
    pamh_greeter.set_tty(Some(ttyname));

    //let sess_greeter = pamh_greeter.open_session(pam_client::Flag::NONE).expect("open greeter session");
    println!("Hello, world! with session");
    println!("press return to close");

    // user authentication
    let (mut pamh_user, user) = loop {
        let mut pamh_user = pam_client::Context::new("textdm", None, pam_client::conv_cli::Conversation::new()).expect("creating usersession conext failed");
        pamh_user.set_tty(Some(ttyname));
        let authres = pamh_user.authenticate(pam_client::Flag::NONE);
        println!("authres: {:?}", authres);
        if let (Ok(_), Ok(username)) = (authres, pamh_user.user()){
            if let Ok(Some(user)) = pwd::Passwd::from_name(&username){
                break (pamh_user, user);
            }
        }
            
    };
    

    // choose desktop session
   
    let sessions = DesktopSession::discover();
    let desktop = loop {
        println!("Choose your session:");
        for (i,s) in sessions.iter().enumerate() {
            println!(" [{}]\t{}", i, s.name);
        }
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("readline");
        if let Ok(i) = input.trim().parse::<usize>() {
            if i < sessions.len() {
                break &sessions[i];
            }
        }
        println!("invalid input! Please try again.");
    };


    // close greeter pam
    //mem::drop(sess_greeter);
    mem::drop(pamh_greeter);

    // start user session
    
    // posix environment
    pamh_user.putenv(&format!("USER={}", user.name)).unwrap();
    pamh_user.putenv(&format!("LOGNAME={}", user.name)).unwrap();
    pamh_user.putenv(&format!("HOME={}", user.dir)).unwrap();
    pamh_user.putenv(&format!("SHELL={}", user.shell)).unwrap();
    // xdg environment, used by pam_systemd
    pamh_user.putenv("XDG_SESSION_CLASS=user").unwrap();
    pamh_user.putenv(&format!("XDG_SESSION_TYPE={}", desktop.typ)).unwrap();
    pamh_user.putenv("XDG_SEAT=seat0");
    pamh_user.putenv("XDG_VTNR=9");
    println!("strip_prefix: {:?}", ttypath.strip_prefix("/dev/tty"));
    println!("ttypath: {:?}", ttypath);
    if let Ok(n) = ttypath.strip_prefix("/dev/tty") {
        if let Some(n) = n.to_str() {
            pamh_user.putenv(&format!("XDG_VTNR={}", n)).unwrap();
        }
    }

    let sess_user = pamh_user.open_session(pam_client::Flag::NONE).expect("open user session");

    println!("Session: {:?}", desktop);
    println!("User: {:?}", user);

    let mut cmd = Command::new("/usr/bin/env");
    if desktop.typ == "x11" {
        cmd.arg("xinit").arg("/usr/bin/env");
    }

    for a in &desktop.argv {
        cmd.arg(a);
    }

    for (k,v) in sess_user.envlist().iter_tuples() {
        println!("Env: {:?}={:?}", k, v);
    }
    cmd.envs(sess_user.envlist().iter_tuples());
    cmd.uid(user.uid);
    cmd.gid(user.gid);
    let c_username = CString::new(user.name).expect("there shouldn't be a \\0 here, as the username comes from a c library");

    let home = user.dir.clone();
    let preexec = move || std::env::set_current_dir(&home);
    unsafe { cmd.pre_exec(preexec); }


    println!("Command: {:?}", cmd);
    println!("starting user session....");

    let _ = unistd::initgroups(&c_username, unistd::Gid::from_raw(user.gid)).map_err(|e| println!("initgroups failed: {:?}", e));
    let mut child = cmd.spawn()?;

    // utmp logging

    // chown tty

    child.wait()?;

    mem::drop(sess_user);
    mem::drop(pamh_user);

    Ok(())
}
