#![allow(non_snake_case)]

mod commands;
mod config;
mod utils;

use colored::Colorize;
use commands::COMMANDS;
use config::WorkspacePaths;
use dialoguer::{Select, theme::ColorfulTheme};

fn printHelp()
{
	println!("{}", "IDA-certiBridge xtask".bold().cyan());
	for cmd in COMMANDS
	{
		println!(
			"  {:<25} {:<12} {}",
			cmd.usage.green(),
			format!("({})", cmd.name).dimmed(),
			cmd.description
		);
	}
}

fn main()
{
	let mut paths = WorkspacePaths::discover();
	let args: Vec<String> = std::env::args().collect();

	if args.len() > 1
	{
		let cmdName = args[1].as_str();
		if cmdName == "help" || cmdName == "--help" || cmdName == "-h"
		{
			printHelp();
			return;
		}

		if let Some(cmd) = COMMANDS.iter().find(|c| c.name == cmdName)
		{
			(cmd.thunk)(&mut paths, &args[2..]);
		}
		else
		{
			printHelp();
		}
		return;
	}

	println!("{}", "IDA-certiBridge Build & Ship".bold().cyan());
	let mut menuItems: Vec<String> = COMMANDS
		.iter()
		.map(|c| format!("{:<10} {}", format!("[{}]", c.name).green(), c.description))
		.collect();
	menuItems.push(format!("{:<10} Exit xtask menu", "[exit]".dimmed()));

	loop
	{
		let selection = match Select::with_theme(&ColorfulTheme::default())
			.with_prompt("Select action")
			.default(0)
			.items(&menuItems)
			.interact_opt()
			.ok()
			.flatten()
		{
			Some(idx) => idx,
			None => break,
		};

		if selection >= COMMANDS.len()
		{
			break;
		}

		(COMMANDS[selection].thunk)(&mut paths, &[]);
		println!();
	}
}
