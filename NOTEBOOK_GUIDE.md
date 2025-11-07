# 📓 Model Training Notebook Guide

## How to Create the Jupyter Notebook

### Method 1: Copy the Code (Recommended)

1. **Create new notebook:**
   ```bash
   jupyter notebook
   ```
   - Click "New" → "Python 3"
   - Save as `model_training.ipynb`

2. **Copy code into cells:**
   - I've provided ONE COMPLETE CODE block above
   - Split it into 12 cells as marked by comments

### Method 2: Cell-by-Cell Structure

Here's how to organize the 12 cells:

---

## 📋 Cell Structure (12 Cells Total)

### **CELL 1: Introduction** (Markdown or Code)
```python
print("""
╔══════════════════════════════════════════════════════════════╗
║   CTI-NLP Enhanced Threat Analyzer - Model Training v2.0    ║
║                                                              ║
║   This notebook trains TWO models:                          ║
║   1. CTI Report Classifier (Sentiment + Severity)           ║
║   2. URL Threat Detector (55 features)                      ║
╚══════════════════════════════════════════════════════════════╝
""")
```
**Run time:** Instant  
**Output:** Welcome message

---

### **CELL 2: Import Libraries**
```python
import pandas as pd
import numpy as np
import re
import pickle
# ... (all imports from the code above)
```
**Run time:** 2-3 seconds  
**Output:** "✓ All libraries imported successfully"

---

### **CELL 3: Configuration**
```python
# CTI Report Configuration
CTI_FILE_PATHS = [...]
CTI_LABEL_COLUMN = 'Threat Category'
# ... (all config from code above)
```
**Run time:** Instant  
**Output:** Configuration summary

---

### **CELL 4: Load CTI Data**
```python
all_dfs = []
for path in CTI_FILE_PATHS:
    try:
        df_part = pd.read_csv(path, usecols=[...])
        # ... (CTI loading code)
```
**Run time:** 1-5 seconds (depends on file size)  
**Output:** Number of records loaded

---

### **CELL 5: Define URL Feature Extraction**
```python
def extract_url_features(url):
    """
    Extracts 55 comprehensive features from a URL
    """
    features = {}
    # ... (complete function from code above)
    return features
```
**Run time:** Instant  
**Output:** Function definition confirmation

---

### **CELL 6: Load URL Data**
```python
try:
    df_url = pd.read_csv(URL_FILE_PATH)
    # ... (URL loading code)
```
**Run time:** 1-10 seconds (depends on dataset size)  
**Output:** Dataset statistics and label distribution

---

### **CELL 7: Extract URL Features**
```python
url_features = df_url[URL_INPUT_COLUMN].apply(
    lambda x: pd.Series(extract_url_features(x))
)
```
**Run time:** 30 seconds to 5 minutes (depends on dataset size)  
**Output:** Progress and feature extraction summary

**⏰ LONGEST CELL** - Be patient!

---

### **CELL 8: Train CTI Model**
```python
# Prepare CTI data
X_cti = df_cti[CTI_FEATURE_COLS]
y_cti = df_cti[CTI_LABEL_COLUMN].astype(str)

# Encode labels
cti_encoder = LabelEncoder()
# ... (CTI training code)

# Save model
with open('model.pkl', 'wb') as f:
    pickle.dump(cti_model, f)
```
**Run time:** 5-10 seconds  
**Output:** 
- Training accuracy
- Files saved (model.pkl, feature_list.pkl, threat_encoder.pkl)

---

### **CELL 9: Train URL Model**
```python
# Prepare URL data
X_url = url_features
y_url = df_url[URL_LABEL_COLUMN]

# Train Random Forest
url_model = RandomForestClassifier(...)
url_model.fit(X_url_train, y_url_train)

# Save model
with open('url_model.pkl', 'wb') as f:
    pickle.dump(url_model, f)
```
**Run time:** 1-3 minutes  
**Output:** 
- Training and test accuracy
- OOB score
- Files saved (url_model.pkl, etc.)

**⏰ SECOND LONGEST CELL**

---

### **CELL 10: Detailed Evaluation**
```python
y_url_pred = url_model.predict(X_url_test)

print("\nClassification Report:")
print(classification_report(...))

print("\nConfusion Matrix:")
print(confusion_matrix(...))

# Feature importance
feature_importance = sorted(...)
```
**Run time:** 5-10 seconds  
**Output:** 
- Classification report
- Confusion matrix
- Top 15 most important features
- Feature importance CSV saved

---

### **CELL 11: Test Predictions**
```python
# Test CTI model
test_cti_samples = [
    {'sentiment': 0.9, 'severity': 1},
    {'sentiment': 0.5, 'severity': 3},
    {'sentiment': 0.2, 'severity': 5}
]

# Test URL model
test_urls = [
    ('https://www.google.com', 'Safe'),
    ('http://secure-paypal-verify.tk', 'Phishing'),
    ...
]
```
**Run time:** 2-3 seconds  
**Output:** 
- Sample CTI predictions
- Sample URL predictions
- Confidence scores

---

### **CELL 12: Final Summary**
```python
print("=" * 60)
print("CELL 12: Training Complete - Summary")
print("=" * 60)

print("\n✓ ALL MODELS TRAINED SUCCESSFULLY!\n")
# ... (summary code)
```
**Run time:** Instant  
**Output:** 
- Complete summary
- All generated files list
- Next steps instructions

---

## 📊 Expected Total Runtime

| Dataset Size | Total Time |
|--------------|------------|
| Small (< 1,000 URLs) | 2-3 minutes |
| Medium (1,000-10,000) | 5-8 minutes |
| Large (10,000-100,000) | 10-15 minutes |
| Very Large (100,000+) | 20-30 minutes |

**Note:** Cell 7 (feature extraction) takes the longest!

---

## 🎯 Quick Copy Instructions

### Option A: Create from scratch
1. Open Jupyter: `jupyter notebook`
2. Create new Python 3 notebook
3. Copy the SINGLE LARGE CODE block I provided above
4. Split it at each `# CELL X:` comment
5. Run all cells: Cell → Run All

### Option B: Use the code directly
Since I provided the code as ONE block, you can:
1. Create 12 cells in Jupyter
2. Copy each section between `# CELL X:` markers
3. Paste into respective cells
4. Run Cell → Run All

---

## 📁 Files Generated After Running

After running all cells, you should have:

```
✓ model.pkl                      (CTI model - ~10-50 KB)
✓ feature_list.pkl               (CTI features - ~1 KB)
✓ threat_encoder.pkl             (CTI encoder - ~1-5 KB)
✓ url_model.pkl                  (URL model - ~5-20 MB)
✓ url_feature_names.pkl          (URL features - ~2 KB)
✓ url_label_encoder.pkl          (URL encoder - ~1 KB)
✓ url_trusted_domains.pkl        (Domains - ~2 KB)
✓ url_feature_importance.csv     (Analysis - ~3 KB)
```

**Total size:** ~5-25 MB (depends on dataset size)

---

## 🔍 Verification Checklist

After running the notebook, verify:

- [ ] All 12 cells executed without errors
- [ ] 8 .pkl files created in project root
- [ ] 1 .csv file created (feature_importance)
- [ ] Final cell shows "ALL MODELS TRAINED SUCCESSFULLY!"
- [ ] Test predictions show reasonable results
- [ ] Total execution time was reasonable (5-30 min)

---

## 🐛 Common Issues & Fixes

### Issue 1: "File not found" in Cell 4 or 6
**Solution:** 
- Check that data files exist in `data/` folder
- Notebook will create sample data if files missing
- You can continue with sample data for testing

### Issue 2: Cell 7 takes forever
**Solution:**
- This is normal for large datasets
- 100,000 URLs = ~5-10 minutes
- Be patient or reduce dataset size for testing

### Issue 3: "Memory Error"
**Solution:**
- Reduce dataset size
- Process in batches
- Increase system RAM
- Close other applications

### Issue 4: Import errors
**Solution:**
```bash
pip install pandas numpy scikit-learn
```

---

## 💡 Tips

1. **Run all at once:** 
   - Cell → Run All
   - Go get coffee ☕
   - Come back in 5-10 minutes

2. **Run incrementally:**
   - Run cells 1-3 (setup)
   - Verify data loads (cells 4, 6)
   - Then run training (cells 8-9)

3. **Testing:**
   - You can skip cells 10-11 if in a hurry
   - They're for analysis only
   - Models are saved after cells 8 & 9

4. **Save often:**
   - Jupyter auto-saves
   - But manually save: Ctrl+S / Cmd+S

---

## 🎓 Understanding the Flow

```
CELL 1-3:   Setup & Configuration (instant)
    ↓
CELL 4:     Load CTI data (5 sec)
    ↓
CELL 5-6:   Load URL data (10 sec)
    ↓
CELL 7:     Extract features (⏰ 1-5 min - LONGEST)
    ↓
CELL 8:     Train CTI model (10 sec)
              ↓
           ✓ SAVES: model.pkl, feature_list.pkl, threat_encoder.pkl
    ↓
CELL 9:     Train URL model (⏰ 1-3 min - SECOND LONGEST)
              ↓
           ✓ SAVES: url_model.pkl, url_feature_names.pkl, url_label_encoder.pkl
    ↓
CELL 10-11: Evaluation & Testing (optional, 10 sec)
    ↓
CELL 12:    Summary & Done! ✅
```

---

## 🚀 Ready to Train!

You now have everything you need:
- ✅ Complete code for all 12 cells
- ✅ Clear structure and timing expectations
- ✅ Troubleshooting guide
- ✅ Verification checklist

**Just copy the code, create the cells, and run!**

---

**Next:** After training completes, go to README.md and follow deployment steps!