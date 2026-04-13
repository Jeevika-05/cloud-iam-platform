const fs = require('fs');
let lines = fs.readFileSync('simulation-engine/cloudshield-attacker/src/main.rs', 'utf8').split('\n');

let inBlock = false;
let blockStartLines = [];
let blockEndLine = -1;
let ipMatch = null;
let agentMatch = null;

let newLines = [];

for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    // Check for start of an attack block (ATK-X)
    let clientMatch = line.match(/let client = ApiClient::new\(&target_url,\s*Some\(["']([^"']+)["']\),\s*Some\(["']([^"']+)["']\)\);/);
    if (clientMatch && line.includes('attack-sim-')) {
        ipMatch = clientMatch[1];
        agentMatch = clientMatch[2];
        
        let corrRegex = /let (atk\d+_correlation_id) = uuid::Uuid::new_v4\(\)\.to_string\(\);/;
        // Peek ahead to find correlation_id
        let corrLine = null;
        for (let j = i + 1; j < i + 30 && j < lines.length; j++) {
            let m = lines[j].match(corrRegex);
            if (m) {
                corrLine = lines[j];
                let corrVarName = m[1];
                
                // Inject the correlation_id generation and new ApiClient inside our newLines
                newLines.push(`        let ${corrVarName} = uuid::Uuid::new_v4().to_string();`);
                newLines.push(`        let client = ApiClient::new(&target_url, Some("${ipMatch}"), Some("${agentMatch}"), Some(&${corrVarName}));`);
                
                // Remove the corrLine from where it normally appears
                // We'll just set a flag or do it via a quick pass below:
                lines[j] = ""; // clear it so it doesn't get pushed later
                break;
            }
        }
    } else if (line.match(/let client = ApiClient::new\(&target_url,\s*Some\(["']127\.0\.0\.1["']\),\s*Some\(["']Sim-Healthcheck["']\)\);/)) {
        newLines.push(`    let client = ApiClient::new(&target_url, Some("127.0.0.1"), Some("Sim-Healthcheck"), None);`);
    } else {
        if (line !== "") {
            newLines.push(line);
        } else if (lines[i] === "" && (i === 0 || lines[i-1] !== "")) {
            newLines.push(line);
        }
    }
}

fs.writeFileSync('simulation-engine/cloudshield-attacker/src/main.rs', newLines.join("\n"));
