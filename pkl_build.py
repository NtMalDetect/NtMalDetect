from __future__ import print_function

import logging
import numpy as np
from optparse import OptionParser
import sys
from time import time
import matplotlib.pyplot as plt

from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.feature_selection import SelectFromModel
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.linear_model import RidgeClassifier
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC
from sklearn.linear_model import SGDClassifier
from sklearn.linear_model import Perceptron
from sklearn.linear_model import PassiveAggressiveClassifier
from sklearn.naive_bayes import BernoulliNB, MultinomialNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neighbors import NearestCentroid
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils.extmath import density
from sklearn import metrics
from sklearn.utils import shuffle



useTFIDF = True
showSampleVector = False
showMostInformativeFeatures = True
howManyInformativeFeatures = 10
nGRAM1 = 10
nGRAM2 = 10
weight = 10

main_corpus = []
main_corpus_target = []

my_categories = ['benign', 'malware']

import glob
import os

malCOUNT = 0
benCOUNT = 0

print("Loading system call database for categories:")
print(my_categories if my_categories else "all")

for filename in glob.glob(os.path.join('./sysMAL', '*.txt')):
    fMAL = open(filename, "r")
    aggregate = ""
    for line in fMAL:
        linea = line[:(len(line)-1)]
        aggregate += " " + linea
    main_corpus.append(aggregate)
    main_corpus_target.append(1)
    malCOUNT += 1

for filename in glob.glob(os.path.join('./sysBEN', '*.txt')):
    fBEN = open(filename, "r")
    aggregate = ""
    for line in fBEN:
        linea = line[:(len(line) - 1)]
        aggregate += " " + linea
    main_corpus.append(aggregate)
    main_corpus_target.append(0)
    benCOUNT += 1



# weight as determined in the top of the code
train_corpus = main_corpus
train_corpus_target = main_corpus_target

# size of datasets

def size_mb(docs):
    return sum(len(s.encode('utf-8')) for s in docs) / 1e6

train_corpus_size_mb = size_mb(train_corpus)

print("Benign Traces: "+str(benCOUNT)+" traces")
print("Malicious Traces: "+str(malCOUNT)+" traces")
print()

print("Extracting features from the training data using a sparse vectorizer...")
t0 = time()


if useTFIDF:
    vectorizer = TfidfVectorizer(ngram_range=(nGRAM1, nGRAM2), min_df=1, use_idf=True, smooth_idf=True) ##############
else:
    vectorizer = CountVectorizer(ngram_range=(nGRAM1, nGRAM2))

X_train = vectorizer.fit_transform(train_corpus)


duration = time() - t0
print("done in %fs at %0.3fMB/s" % (duration, train_corpus_size_mb / duration))
print("n_samples: %d, n_features: %d" % X_train.shape)
print()

clf_MultiNB = MultinomialNB(alpha=.01)



print('_'*60)
print("Training the following classifier: ", clf_MultiNB)

t0 = time()

clf_MultiNB.fit(X_train, train_corpus_target)

train_time = time() - t0
print("train time: %0.3fs" % train_time)
print('_'*60)



clf_LSVC = Pipeline([
  ('feature_selection', SelectFromModel(LinearSVC(penalty="l1", dual=False,
                                                  tol=1e-3))),
  ('classification', LinearSVC(penalty="l2"))])


print('_'*60)
print("Training the following classifier: ", clf_LSVC)

t0 = time()
clf_LSVC.fit(X_train, train_corpus_target)


train_time = time() - t0
print("train time: %0.3fs" % train_time)
print('_'*60)


print('Generating re-usable pickles...')
from sklearn.externals import joblib

joblib.dump(clf_MultiNB, './pickles/classifier_MultiNB.pkl')
joblib.dump(clf_LSVC, './pickles/classifier_Linear_SVC.pkl')
joblib.dump(vectorizer, './pickles/vectorizer.pkl')
