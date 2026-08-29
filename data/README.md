# MailShield Dataset Documentation

## Overview
This directory contains dataset resources used for training and evaluating the Machine Learning Spam Classifier component of MailShield.

## Dataset: `sample_emails.csv`
- **Format**: CSV (Comma-Separated Values)
- **Columns**:
  - `label`: Binary classification target (`spam` for spam/phishing or `ham` for legitimate/safe)
  - `category`: Fine-grained categorization (`ham_business`, `ham_personal`, `ham_transactional`, `spam_promotional`, `phishing_credential`, `phishing_banking`, `phishing_urgency`)
  - `subject`: Email subject line
  - `body`: Full email body text

## Dataset Provenance & Academic Reference
1. **Enron Spam Dataset**: Standard academic corpus of legitimate organizational emails and spam.
2. **SMS Spam Collection / SpamAssassin Public Corpus**: Public domain benchmark datasets for text-based spam detection research.
3. **Phishing Corpus (Nazario Phishing Corpus)**: Verified academic archives of real-world phishing emails.

## How to Train the Model
Run the following command from the project root:

```bash
python ml/train_model.py
```

This will:
1. Load `data/sample_emails.csv`
2. Perform text normalization and tokenization via `ml/preprocessing.py`
3. Split the dataset into training (80%) and testing (20%) sets
4. Fit a TF-IDF vectorizer (with unigram and bigram features, sublinear term frequency scaling)
5. Train a calibrated Multinomial Naive Bayes classifier
6. Compute performance metrics (Accuracy, Precision, Recall, F1-Score, Confusion Matrix)
7. Save serialized model artifacts:
   - `models/spam_vectorizer.pkl`
   - `models/spam_classifier.pkl`
   - `models/evaluation_metrics.json`
