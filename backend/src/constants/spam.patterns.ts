const SPAM_PATTERNS = { 
    KEYWORDS: [
        'buy now', 'free money', 'click here', 'earn fast', 'make money',
        'casino', 'forex', 'crypto mining', 'get rich', 'betting',
        'unlimited income', 'work from home', '100% free'
    ],
    SUSPICIOUS_DOMAINS: [ 
        'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'adf.ly',
        'ow.ly', 'rebrandly', 'cutt.ly', 'shorturl'
    ],
    MIN_DESCRIPTION_LENGTH: 20, // Minimum length for description to avoid spam
    MIN_TITLE_LENGTH: 5, // Minimum length for title to avoid spam
    MIN_FILES_COUNT: 3, // Minimum number of files to consider a valid submission
    MAX_IDENTICAL_SUBMISSIONS: 3 // Maximum number of identical repo submissions allowed
};

export default SPAM_PATTERNS;