#![allow(non_snake_case)]

use colored::Colorize;
use std::path::Path;
use std::process::{Command, Stdio};

fn getTimestamp() -> String
{
	#[repr(C)]
	struct SystemTime
	{
		wYear: u16,
		wMonth: u16,
		wDayOfWeek: u16,
		wDay: u16,
		wHour: u16,
		wMinute: u16,
		wSecond: u16,
		wMilliseconds: u16,
	}
	unsafe extern "system"
	{
		fn GetLocalTime(lpSystemTime: *mut SystemTime);
	}
	let mut st = std::mem::MaybeUninit::<SystemTime>::uninit();
	unsafe
	{
		GetLocalTime(st.as_mut_ptr());
		let st = st.assume_init();
		format!("{:02}:{:02}:{:02}", st.wHour, st.wMinute, st.wSecond)
	}
}

pub fn logWithTime(msg: &str)
{
	let ts = getTimestamp();
	println!("[{}] {}", ts.dimmed(), msg);
}

pub fn runCommand(cmd: &str, args: &[&str], dir: &Path) -> bool
{
	let status = Command::new(cmd)
		.args(args)
		.current_dir(dir)
		.stdout(Stdio::inherit())
		.stderr(Stdio::inherit())
		.status();

	matches!(status, Ok(s) if s.success())
}
