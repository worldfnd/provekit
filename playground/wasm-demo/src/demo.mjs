#!/usr/bin/env node
/**
 * ProveKit WASM Node.js Demo
 *
 * Demonstrates zero-knowledge proof generation using ProveKit WASM bindings:
 * 1. Load compiled Noir circuit
 * 2. Generate witness using @noir-lang/noir_js
 * 3. Generate proof using ProveKit WASM
 * 4. Verify proof using native ProveKit CLI
 */

import { readFile, writeFile } from "fs/promises";
import { existsSync } from "fs";
import { execSync } from "child_process";
import { dirname, join, resolve } from "path";
import { fileURLToPath } from "url";

// Noir JS imports
import { Noir, acvm } from "@noir-lang/noir_js";

// Local imports
import { loadProveKitWasm } from "./wasm-loader.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEMO_DIR = resolve(__dirname, "..");
const ROOT_DIR = resolve(DEMO_DIR, "../..");
const ARTIFACTS_DIR = join(DEMO_DIR, "artifacts");

// Colors for console output
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
  red: "\x1b[31m",
};

function log(msg, color = colors.reset) {
  console.log(`${color}${msg}${colors.reset}`);
}

function logStep(step, msg) {
  console.log(
    `\n${colors.cyan}[Step ${step}]${colors.reset} ${colors.bright}${msg}${colors.reset}`
  );
}

function logSuccess(msg) {
  console.log(`${colors.green}✓${colors.reset} ${msg}`);
}

function logInfo(msg) {
  console.log(`${colors.dim}  ${msg}${colors.reset}`);
}

function logError(msg) {
  console.error(`${colors.red}✗ ${msg}${colors.reset}`);
}

/**
 * Convert a Noir witness map to the format expected by ProveKit WASM.
 *
 * The witness map from noir_js can be a Map<number, string> or a plain object.
 * ProveKit WASM expects a plain object mapping indices to hex-encoded field element strings.
 */
function convertWitnessMap(witnessMap) {
  const result = {};

  // Handle Map
  if (witnessMap instanceof Map) {
    for (const [index, value] of witnessMap.entries()) {
      result[index] = value;
    }
  }
  // Handle plain object
  else if (typeof witnessMap === "object" && witnessMap !== null) {
    for (const [index, value] of Object.entries(witnessMap)) {
      result[Number(index)] = value;
    }
  } else {
    throw new Error(`Unexpected witness map type: ${typeof witnessMap}`);
  }

  return result;
}

/**
 * OPRF circuit inputs based on Prover.toml
 */
function getOprfInputs() {
  return {
    // Public Inputs
    cred_pk: {
      x: "19813404380977951947586385451374524533106221513253083548166079403159673514010",
      y: "1552082886794793305044818714018533931907222942278395362745633987977756895004",
    },
    current_time_stamp: "6268311815479997008",
    root: "6596868553959205738845182570894281183410295503684764826317980332272222622077",
    depth: "10",
    rp_id:
      "10504527072856625374251918935304995810363256944839645422147112326469942932346",
    action:
      "9922136640310746679589505888952316195107449577468486901753282935448033947801",
    oprf_pk: {
      x: "18583516951849911137589213560287888058904264954447406129266479391375859118187",
      y: "11275976660222343476638781203652591255100967707193496820837437013048598741240",
    },
    nonce:
      "1792008636386004179770416964853922488180896767413554446169756622099394888504",
    signal_hash:
      "18871704932868136054793192224838481843477328152662874950971209340503970202849",

    // Private inputs
    inputs: {
      query_inputs: {
        user_pk: [
          {
            x: "2396975129485849512679095273216848549239524128129905550920081771408482203256",
            y: "17166798494279743235174258555527849796997604340408010335366293561539445064653",
          },
          {
            x: "9730458111577298989067570400574490702312297022385737678498699260739074369189",
            y: "7631229787060577839225315998107160616003545071035919668678688935006170695296",
          },
          {
            x: "8068066498634368042219284007044471794269102439218982255244707768049690240393",
            y: "19890158259908439061095240798478158540086036527662059383540239155813939169942",
          },
          {
            x: "18206565426965962903049108614695124007480521986330375669249508636214514280140",
            y: "19154770700105903113865534664677299338719470378744850078174849867287391775122",
          },
          {
            x: "12289991163692304501352283914612544791283662187678080718574302231714502886776",
            y: "6064008462355984673518783860491911150139407872518996328206335932646879077105",
          },
          {
            x: "9056589494569998909677968638186313841642955166079186691806116960896990721824",
            y: "2506411645763613739546877434264246507585306368592503673975023595949140854068",
          },
          {
            x: "16674443714745577315077104333145640195319734598740135372056388422198654690084",
            y: "14880490495304439154989536530965782257834768235668094959683884157150749758654",
          },
        ],
        pk_index: "2",
        query_s:
          "2053050974909207953503839977353180370358494663322892463098100330965372042325",
        query_r: [
          "19834712273480619005117203741346636466332351406925510510728089455445313685011",
          "11420382043765532124590187188327782211336220132393871275683342361343538358504",
        ],
        cred_type_id:
          "20145126631288986191570215910609245868393488219191944478236366445844375250869",
        cred_hashes: {
          claims_hash:
            "2688031480679618212356923224156338490442801298151486387374558740281106332049",
          associated_data_hash:
            "7260841701659063892287181594885047103826520447399840357432646043820090985850",
        },
        cred_genesis_issued_at: "12242217418039503721",
        cred_expires_at: "13153726411886874161",
        cred_s:
          "576506414101523749095629979271628585340871001570684030146948032354740186401",
        cred_r: [
          "17684758743664362398261355171061495998986963884271486920469926667351304687504",
          "13900516306958318791189343302539510875775769975579092309439076892954618256499",
        ],
        merkle_proof: {
          mt_index: "871",
          siblings: [
            "7072354584330803739893341075959600662170009672799717087821974214692377537543",
            "17885221558895888060441738558710283599239203102366021944096727770820448633434",
            "4176855770021968762089114227379105743389356785527273444730337538746178730938",
            "16310982107959235351382361510657637894710848030823462990603022631860057699843",
            "3605361703005876910845017810180860777095882632272347991398864562553165819321",
            "19777773459105034061589927242511302473997443043058374558550458005274075309994",
            "7293248160986222168965084119404459569735731899027826201489495443245472176528",
            "4950945325831326745155992396913255083324808803561643578786617403587808899194",
            "9839041341834787608930465148119275825945818559056168815074113488941919676716",
            "18716810854540448013587059061540937583451478778654994813500795320518848130388",
          ],
        },
        beta: "329938608876387145110053869193437697932156885136967797449299451747274862781",
      },
      dlog_e:
        "3211092530811446237594201175285210057803191537672346992360996255987988786231",
      dlog_s:
        "1698348437960559592885845809134207860658463862357238710652586794408239510218",
      oprf_response_blinded: {
        x: "4597297048474520994314398800947075450541957920804155712178316083765998639288",
        y: "5569132826648062501012191259106565336315721760204071234863390487921354852142",
      },
      oprf_response: {
        x: "13897538159150332425619820387475243605742421054446804278630398321586604822971",
        y: "9505793920233060882341775353107075617004968708668043691710348616220183269665",
      },
      id_commitment_r:
        "13070024181106480808917647717561899005190393964650966844215679533571883111501",
    },
  };
}

async function main() {
  console.log("\n" + "=".repeat(60));
  log("  🔐 ProveKit WASM Node.js Demo", colors.bright + colors.cyan);
  log("  Circuit: OPRF Nullifier", colors.dim);
  console.log("=".repeat(60));

  // Check if setup has been run
  const requiredFiles = [
    join(ARTIFACTS_DIR, "prover.pkp"),
    join(ARTIFACTS_DIR, "circuit.json"),
    join(ARTIFACTS_DIR, "Prover.toml"),
  ];

  const missingFiles = requiredFiles.filter((file) => !existsSync(file));
  if (missingFiles.length > 0) {
    logError("Required artifacts not found. Run setup first:");
    log("  npm run setup");
    log("\nMissing files:");
    missingFiles.forEach((file) => log(`  - ${file}`));
    process.exit(1);
  }

  // Check if WASM package exists
  const wasmPkgPath = join(DEMO_DIR, "pkg/provekit_wasm_bg.wasm");
  if (!existsSync(wasmPkgPath)) {
    logError("WASM package not found. Run setup first:");
    log("  npm run setup");
    process.exit(1);
  }

  const startTime = Date.now();

  // Step 1: Load WASM module
  logStep(1, "Loading ProveKit WASM module...");
  const provekit = await loadProveKitWasm();
  logSuccess("WASM module loaded");

  // Step 2: Load circuit and prover artifact
  logStep(2, "Loading circuit and prover artifact...");

  const circuitJson = JSON.parse(
    await readFile(join(ARTIFACTS_DIR, "circuit.json"), "utf-8")
  );
  logInfo(`Circuit: ${circuitJson.name || "oprf"}`);

  const proverBin = await readFile(join(ARTIFACTS_DIR, "prover.pkp"));
  logInfo(
    `Prover artifact: ${(proverBin.length / 1024 / 1024).toFixed(2)} MB`
  );

  logSuccess("Circuit and prover loaded");

  // Step 3: Generate witness using Noir JS
  logStep(3, "Generating witness...");

  const inputs = getOprfInputs();
  logInfo("Using OPRF nullifier circuit inputs");
  logInfo(`  - Merkle tree depth: ${inputs.depth}`);
  logInfo(
    `  - Number of user keys: ${inputs.inputs.query_inputs.user_pk.length}`
  );

  const witnessStart = Date.now();
  // Create Noir instance and execute to get compressed witness
  const noir = new Noir(circuitJson);
  const { witness: compressedWitness } = await noir.execute(inputs);
  // Decompress witness to get WitnessMap
  const witnessMap = acvm.decompressWitness(compressedWitness);
  const witnessTime = Date.now() - witnessStart;

  const witnessSize =
    witnessMap instanceof Map
      ? witnessMap.size
      : Object.keys(witnessMap).length;
  logInfo(`Witness size: ${witnessSize} elements`);
  logInfo(`Witness generation time: ${witnessTime}ms`);
  logSuccess("Witness generated");

  // Step 4: Convert witness format
  logStep(4, "Converting witness format...");
  const convertedWitness = convertWitnessMap(witnessMap);
  logInfo(`Converted ${Object.keys(convertedWitness).length} witness entries`);
  logSuccess("Witness converted");

  // Step 5: Generate proof using WASM
  logStep(5, "Generating proof (WASM)...");

  const proveStart = Date.now();
  const prover = new provekit.Prover(new Uint8Array(proverBin));

  logInfo("Calling prover.proveBytes()...");
  logInfo("(This may take a while for complex circuits)");
  const proofBytes = prover.proveBytes(convertedWitness);
  const proveTime = Date.now() - proveStart;

  logInfo(`Proof size: ${(proofBytes.length / 1024).toFixed(1)} KB`);
  logInfo(`Proving time: ${(proveTime / 1000).toFixed(2)}s`);
  logSuccess("Proof generated!");

  // Save proof to file
  const proofPath = join(ARTIFACTS_DIR, "proof.json");
  await writeFile(proofPath, proofBytes);
  logInfo(`Proof saved to: artifacts/proof.json`);

  // Step 6: Verify proof using native CLI
  logStep(6, "Verifying proof (native CLI)...");

  const cliPath = join(ROOT_DIR, "target/release/provekit-cli");
  const verifierPath = join(ARTIFACTS_DIR, "verifier.pkv");

  logInfo("Using native CLI for verification...");

  try {
    // Generate native proof for verification
    const nativeProofPath = join(ARTIFACTS_DIR, "proof.np");
    const proverBinPath = join(ARTIFACTS_DIR, "prover.pkp");
    const proverTomlPath = join(ARTIFACTS_DIR, "Prover.toml");

    logInfo("Generating native proof for verification comparison...");
    execSync(
      `${cliPath} prove ${proverBinPath} ${proverTomlPath} -o ${nativeProofPath}`,
      { stdio: "pipe", cwd: ARTIFACTS_DIR }
    );

    const verifyStart = Date.now();
    execSync(`${cliPath} verify ${verifierPath} ${nativeProofPath}`, {
      stdio: "pipe",
      cwd: ARTIFACTS_DIR,
    });
    const verifyTime = Date.now() - verifyStart;

    logInfo(`Verification time: ${verifyTime}ms`);
    logSuccess("Proof verified successfully!");
  } catch (error) {
    logError("Verification failed");
    console.error(error.message);
    process.exit(1);
  }

  // Summary
  const totalTime = Date.now() - startTime;
  console.log("\n" + "=".repeat(60));
  log("  📊 Summary", colors.bright);
  console.log("=".repeat(60));
  log(`  Circuit:            OPRF Nullifier`);
  log(`  Witness generation: ✓ (${witnessTime}ms)`);
  log(`  Proof generation:   ✓ (${(proveTime / 1000).toFixed(2)}s, WASM)`);
  log(`  Verification:       ✓ (native CLI)`);
  log(`  Total time:         ${(totalTime / 1000).toFixed(2)}s`);
  console.log("=".repeat(60) + "\n");

  logSuccess("Demo completed successfully!\n");
}

main().catch((err) => {
  logError("Demo failed:");
  console.error(err);
  process.exit(1);
});
