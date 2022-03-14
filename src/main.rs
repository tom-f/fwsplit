use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use serde_json::Result;
use std::io;

fn main() -> Result<()> {
    let mut input = String::new();

    loop {
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(len) => {
                if len == 0 {
                    // reached 'end' of piped input
                    break;
                } else {
                    input.push_str(&line)
                }
            }
            Err(error) => println!("could not read from piped input {:?}", error),
        }
    }

    let v: WAFConfig = serde_json::from_str(&input)?;

    let rules = serde_json::to_string_pretty(&v.disabled_rule_groups).unwrap();
    let exclusions = serde_json::to_string_pretty(&v.exclusions).unwrap();

    let rules = format_output(rules);
    let exclusions = format_output(exclusions);

    println!("got:\n{}\n", rules);
    println!("got:\n {}\n", exclusions);

    Ok(())
}

fn format_output(mut rules: String) -> String {
    let braces_re = Regex::new(r#"},\n\s\s"#).unwrap();
    let quotes_re = Regex::new(r#""(\w+)":"#).unwrap();
    rules = braces_re.replace_all(&rules, "}, ").to_string();
    rules = quotes_re
        .replace_all(&rules, |caps: &Captures| format!("{} =", &caps[1]))
        .to_string();
    rules = rules.replace("  ", "    ");
    rules.replace("\",", "\"")
    // rules
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all(deserialize = "camelCase"))]
struct WAFConfig {
    disabled_rule_groups: Vec<DisabledRule>,
    exclusions: Vec<WAFExclusion>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all(deserialize = "camelCase"))]
struct DisabledRule {
    rule_group_name: String,
    rules: Vec<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all(deserialize = "camelCase"))]
struct WAFExclusion {
    match_variable: String,
    selector: String,
    selector_match_operator: String,
}

// #[test]
// fn regex_test() {
//     let quotes_re = Regex::new(r#".*"(\w+)":.*"#).unwrap();
//     let subj = "";

//     quotes_re.re
// }
