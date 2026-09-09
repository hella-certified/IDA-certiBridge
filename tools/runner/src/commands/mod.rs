pub mod build;
pub mod config;
pub mod deploy;

use crate::config::WorkspacePaths;

pub struct CommandDef
{
	pub name: &'static str,
	pub usage: &'static str,
	pub description: &'static str,
	pub thunk: fn(&mut WorkspacePaths, &[String]),
}

pub const COMMANDS: &[CommandDef] = &[
	CommandDef
	{
		name: "build",
		usage: "xtask build",
		description: "Build C++ core daemon binary and ship to IDA plugins",
		thunk: build::run,
	},
	CommandDef
	{
		name: "deploy",
		usage: "xtask deploy [path]",
		description: "Ship plugin components and daemon to IDA plugins directory",
		thunk: deploy::run,
	},
	CommandDef
	{
		name: "config",
		usage: "xtask config [path]",
		description: "Configure IDA directory or plugins directory path",
		thunk: config::run,
	},
];
