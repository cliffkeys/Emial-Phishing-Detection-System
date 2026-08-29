import re
import string


def clean_email_text(text: str) -> str:
    """
    Cleans and normalizes email subject and body text for ML vectorization.
    
    Steps:
    1. Convert to lowercase
    2. Replace URLs with a special token: HTTP_URL_TOKEN
    3. Replace Email addresses with a special token: EMAIL_ADDR_TOKEN
    4. Replace Currency/Dollar symbols with special token: CURRENCY_TOKEN
    5. Replace numbers with NUMBER_TOKEN
    6. Normalize whitespace and remove non-ASCII / excessive punctuation
    """
    if not text:
        return ""
    
    # Lowercase
    cleaned = text.lower()

    # Mask URLs
    cleaned = re.sub(
        r"https?://\S+|www\.\S+",
        " HTTP_URL_TOKEN ",
        cleaned
    )

    # Mask Email addresses
    cleaned = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        " EMAIL_ADDR_TOKEN ",
        cleaned
    )

    # Mask Currency symbols and monetary amounts
    cleaned = re.sub(r"[\$£€¥]\s*\d+([.,]\d+)?", " CURRENCY_AMOUNT_TOKEN ", cleaned)
    cleaned = re.sub(r"[\$£€¥]", " CURRENCY_TOKEN ", cleaned)

    # Mask standalone large numbers
    cleaned = re.sub(r"\b\d{2,}\b", " NUMBER_TOKEN ", cleaned)

    # Replace multiple exclamation marks or question marks
    cleaned = re.sub(r"!{2,}", " MULTI_EXCLAMATION ", cleaned)
    cleaned = re.sub(r"\?{2,}", " MULTI_QUESTION ", cleaned)

    # Remove standard punctuation but keep our tokens intact
    # Strip characters that are not alphanumeric, whitespace, or underscore
    cleaned = re.sub(r"[^\w\s_]", " ", cleaned)

    # Collapse multiple whitespaces
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    return cleaned
