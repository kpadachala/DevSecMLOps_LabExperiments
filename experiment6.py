"""Secure email threat detection demo. Supports a CSV with text and label columns."""
import argparse, csv, json
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.pipeline import Pipeline

SAMPLE = [
('Team meeting moved to 10 AM tomorrow','ham'),('Please review the project notes before class','ham'),('Your invoice is attached for your records','ham'),('Can we reschedule our appointment for Friday','ham'),('Thanks for sending the assignment details','ham'),('The lab session starts at nine in the morning','ham'),('Reminder submit your timesheet by end of day','ham'),('Here are the minutes from yesterday meeting','ham'),('Congratulations you have won a free prize claim now','spam'),('URGENT claim your cash reward click this link','spam'),('Earn money fast with no work required','spam'),('You are selected for a FREE gift card act now','spam'),('Limited offer buy now and win big cash','spam'),('Your account won a lottery send details immediately','spam'),('Get cheap loans instantly click to apply','spam'),('Exclusive deal claim your prize before it expires','spam'),('Winner claim your free bonus today','spam'),('Make thousands from home guaranteed profit','spam'),('Please find the meeting agenda attached','ham'),('Could you share the notes after the lecture','ham'),('Your package is scheduled for delivery tomorrow','ham'),('The report is ready for your feedback','ham'),('Click here now to claim your cash bonus','spam'),('Act fast free money waiting for you','spam')]

def load_rows(path):
    if not path: return SAMPLE, 'Built-in synthetic demonstration samples (not the full corpus)'
    with open(path, newline='', encoding='utf-8-sig') as f:
        rows=[]
        for r in csv.DictReader(f):
            text=r.get('text') or r.get('message') or r.get('body')
            label=(r.get('label') or r.get('category') or r.get('class') or '').strip().lower()
            if text and label in {'spam','ham'}: rows.append((text,label))
    if len(rows)<10: raise ValueError('CSV needs at least 10 valid rows and text/message plus label/category columns; labels must be ham or spam.')
    return rows, 'User-provided labeled CSV: '+path

def main():
    p=argparse.ArgumentParser(); p.add_argument('--data'); p.add_argument('--output',default='results.json'); a=p.parse_args()
    rows,source=load_rows(a.data); X=[x for x,y in rows]; y=[y for x,y in rows]
    model=Pipeline([('tfidf',TfidfVectorizer(lowercase=True,stop_words='english',ngram_range=(1,2),max_features=5000)),('classifier',LogisticRegression(max_iter=1000,class_weight='balanced',random_state=42))])
    if min(y.count('ham'),y.count('spam'))>=2 and len(y)>=10:
        Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.25,random_state=42,stratify=y); model.fit(Xtr,ytr); pred=model.predict(Xte); truth=yte; evaluation='Stratified 25% holdout'
    else:
        model.fit(X,y); pred=model.predict(X); truth=y; evaluation='Training-set demo; metrics are not an unbiased evaluation'
    result={'experiment':'Secure Email Threat Detection Using DevSecMLOps','dataset':source,'samples':len(rows),'evaluation':evaluation,'parameters':'TF-IDF (ngram_range=(1,2), max_features=5000) | Logistic Regression (max_iter=1000, class_weight=balanced, random_state=42)','accuracy':round(accuracy_score(truth,pred),4),'precision_spam':round(precision_score(truth,pred,pos_label='spam',zero_division=0),4),'recall_spam':round(recall_score(truth,pred,pos_label='spam',zero_division=0),4),'f1_spam':round(f1_score(truth,pred,pos_label='spam',zero_division=0),4)}
    Path(a.output).write_text(json.dumps(result,indent=2),encoding='utf-8'); print(json.dumps(result,indent=2)); print('Saved:',a.output)
if __name__=='__main__': main()
