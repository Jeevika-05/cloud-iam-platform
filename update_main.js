const fs = require('fs');
let content = fs.readFileSync('simulation-engine/cloudshield-attacker/src/main.rs', 'utf8');

content = content.replace(/let client = ApiClient::new\(&target_url,\s*Some\("([^"]+)"\),\s*Some\("([^"]+)"\)\);([\s\S]*?)let (atk\d+_correlation_id) = uuid::Uuid::new_v4\(\)\.to_string\(\);/g, (match, ip, agent, middle, corr_id) => {
    return `let ${corr_id} = uuid::Uuid::new_v4().to_string();\n        let client = ApiClient::new(&target_url, Some("${ip}"), Some("${agent}"), Some(&${corr_id}));${middle}`;
});

content = content.replace(/ApiClient::new\(&target_url, Some\("127.0.0.1"\), Some\("Sim-Healthcheck"\)\)/g, 'ApiClient::new(&target_url, Some("127.0.0.1"), Some("Sim-Healthcheck"), None)');

fs.writeFileSync('simulation-engine/cloudshield-attacker/src/main.rs', content);
