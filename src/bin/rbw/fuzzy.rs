// fuzzy matching for the tui: every character of the pattern has to appear
// in the text in order, and matches score higher when they are consecutive or
// start a word, like in fzf

// the score of the best match of pattern in text, or None if it doesn't
// match. pattern is expected to be lowercase already.
pub fn score(pattern: &str, text: &str) -> Option<i64> {
    let pattern: Vec<char> = pattern.chars().collect();
    if pattern.is_empty() {
        return Some(0);
    }
    let text: Vec<char> = text.chars().flat_map(char::to_lowercase).collect();
    if text.len() < pattern.len() {
        return None;
    }

    // best[j] is the best score of matching pattern[..=i] with the match of
    // pattern[i] at text[j], for the current i
    let mut best: Vec<Option<i64>> = vec![None; text.len()];
    for (i, &p) in pattern.iter().enumerate() {
        let mut next = vec![None; text.len()];
        // the best score for pattern[..i] ending strictly before j
        let mut prefix_best: Option<i64> = None;
        for j in 0..text.len() {
            if i > 0 && j > 0 {
                // gaps are slightly penalized, so tighter matches win
                prefix_best = match (prefix_best, best[j - 1]) {
                    (Some(a), Some(b)) => Some(a.max(b) - 1),
                    (a, b) => a.map(|a| a - 1).or(b),
                };
            }
            if text[j] != p {
                continue;
            }
            let mut bonus = 1;
            if j == 0 || !text[j - 1].is_alphanumeric() {
                bonus += 8;
            }
            let score = if i == 0 {
                Some(bonus - i64::try_from(j).unwrap_or(i64::MAX).min(10))
            } else {
                let consecutive = (j > 0)
                    .then(|| best[j - 1])
                    .flatten()
                    .map(|s| s + bonus + 6);
                let gapped = prefix_best.map(|s| s + bonus);
                match (consecutive, gapped) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                }
            };
            next[j] = score;
        }
        best = next;
    }
    best.into_iter().flatten().max()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_score() {
        assert_eq!(score("", "anything"), Some(0));
        assert!(score("ghb", "GitHub").is_some());
        assert!(score("hg", "GitHub").is_none());
        assert!(score("xyz", "ab").is_none());
        // consecutive matches beat scattered ones
        assert!(score("git", "GitLab") > score("git", "Google Inc Tokens"));
        // word starts beat matches in the middle of a word
        assert!(score("hub", "My Hub") > score("hub", "GitHub"));
        assert!(score("gh", "GitHub") > score("gh", "Laugh"));
    }
}
