use std::path::PathBuf;

use structopt::StructOpt;

use crate::crs::create_crs;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Debug, StructOpt)]
enum SubCommand {
    #[structopt(name = "crs")]
    Crs(CrsCommand),
    // #[structopt(name = "setup")]
    // Setup {
    //     #[structopt(parse(from_os_str))]
    //     pk_path: PathBuf,
    //     #[structopt(parse(from_os_str))]
    //     vk_path: PathBuf,
    // },
    // #[structopt(name = "prove")]
    // Prove {
    //     #[structopt(parse(from_os_str))]
    //     pk_path: PathBuf,
    //     #[structopt(parse(from_os_str))]
    //     input_path: PathBuf,
    //     #[structopt(parse(from_os_str))]
    //     proof_path: PathBuf,
    //     #[structopt(parse(from_os_str))]
    //     public_wires_path: PathBuf,
    // },
    // #[structopt(name = "verify")]
    // Verify {
    //     #[structopt(parse(from_os_str))]
    //     vk_path: PathBuf,
    //     #[structopt(parse(from_os_str))]
    //     proof_path: PathBuf,
    //     #[structopt(parse(from_os_str))]
    //     public_wires_path: PathBuf,
    // },
}

#[derive(Debug, StructOpt)]
enum CrsCommand {
    #[structopt(name = "create")]
    Create {
        #[structopt(default_value = "23")]
        log2_size: usize,
        #[structopt(short, long, parse(from_os_str), default_value = "./test_cases/crs")]
        path: PathBuf,
    },
}

pub fn invoke_command() -> anyhow::Result<()> {
    match Cli::from_args().subcommand {
        SubCommand::Crs(crs_command) => match crs_command {
            CrsCommand::Create { log2_size, path } => {
                create_crs(log2_size, &path);
            }
        },
        // SubCommand::Setup { pk_path, vk_path } => {
        //     // crate::api::ipa::setup::generate_random_parameters_with_file(&pk_path, &vk_path)?;
        //     generate_random_parameters_with_file(&pk_path, &vk_path)?;
        // }
        // SubCommand::Prove {
        //     pk_path,
        //     input_path,
        //     proof_path,
        //     public_wires_path,
        // } => {
        //     create_random_proof_with_file(&pk_path, &input_path, &proof_path, &public_wires_path)?;
        // }
        // SubCommand::Verify {
        //     vk_path,
        //     proof_path,
        //     public_wires_path,
        // } => {
        //     verify_proof_with_file(&vk_path, &proof_path, &public_wires_path)?;
        // }
    }

    Ok(())
}
