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

ask = input("Do you want to specify parameters or use default values? Input 'T' or 'F'.   ")
if ask == "T":
    useTFIDFStr = input("Do you want to use tfidfVectorizer or CountVectorizer? Type T for tfidfVectorizer and F for CountVectorizer   ")
    if useTFIDFStr == "T":
        useTFIDF = True
    else:
        useTFIDF = False

    showSampleVectorStr = input("Do you want to print an example vectorized corpus? (T/F)   ")
    if showSampleVectorStr == "T":
        showSampleVector = True
    else:
        showSampleVector = False

    showMostInformativeFeaturesStr = input("Do you want to print the most informative feature in some of the classifiers? (T/F)   ")
    if showMostInformativeFeaturesStr == "T":
        showMostInformativeFeatures = True
        howManyInformativeFeatures = int(input("How many of these informative features do you want to print for each binary case? Input a number   "))
    else:
        showMostInformativeFeatures = False

    nGRAM1 = int(input("N-Gram lower bound (Read README.md for more information)? Input a number   "))
    nGRAM2 = int(input("N-Gram Upper bound? Input a number   "))
    weight = int(input("What weight do you want to use to separate train & testing? Input a number   "))


main_corpus = []
main_corpus_target = []

my_categories = ['benign', 'malware']

# feeding corpus the testing data

print("Loading system call database for categories:")
print(my_categories if my_categories else "all")


import glob
import os

malCOUNT = 0
benCOUNT = 0
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

# shuffling the dataset
main_corpus_target, main_corpus = shuffle(main_corpus_target, main_corpus, random_state=0)




# weight as determined in the top of the code
train_corpus = main_corpus[:(weight*len(main_corpus)//(weight+1))]
train_corpus_target = main_corpus_target[:(weight*len(main_corpus)//(weight+1))]
test_corpus = main_corpus[(len(main_corpus)-(len(main_corpus)//(weight+1))):]
test_corpus_target = main_corpus_target[(len(main_corpus)-len(main_corpus)//(weight+1)):]




print("%d documents - %0.3fMB (training set)" % (
    len(train_corpus_target), train_corpus_size_mb))
print("%d documents - %0.3fMB (test set)" % (
    len(test_corpus_target), test_corpus_size_mb))
print("%d categories" % len(my_categories))
print()
print("Benign Traces: "+str(benCOUNT)+" traces")
print("Malicious Traces: "+str(malCOUNT)+" traces")
print()



print("Extracting features from the training data using a sparse vectorizer...")
t0 = time()

if useTFIDF:
    vectorizer = TfidfVectorizer(ngram_range=(nGRAM1, nGRAM2), min_df=1, use_idf=True, smooth_idf=True) ##############
else:
    vectorizer = CountVectorizer(ngram_range=(nGRAM1, nGRAM2))

analyze = vectorizer.build_analyzer()

if showSampleVector:
    print(analyze(test_corpus[1]))

X_train = vectorizer.fit_transform(train_corpus)



duration = time() - t0
print("done in %fs at %0.3fMB/s" % (duration, train_corpus_size_mb / duration))
print("n_samples: %d, n_features: %d" % X_train.shape)
print()

print("Extracting features from the test data using the same vectorizer...")
t0 = time()
X_test = vectorizer.transform(test_corpus)
duration = time() - t0
print("done in %fs at %0.3fMB/s" % (duration, test_corpus_size_mb / duration))
print("n_samples: %d, n_features: %d" % X_test.shape)
print()


# show which are the definitive features
def show_most_informative_features(vectorizer, clf, n=20):
    feature_names = vectorizer.get_feature_names()
    coefs_with_fns = sorted(zip(clf.coef_[0], feature_names))
    coefs_with_fns_mal = coefs_with_fns[:-(n + 1):-1]
    coefs_with_fns = sorted(zip(clf.coef_[0], feature_names))[:n]

    print()
    print("Most Informative Benign Features:")
    for (coef_1, fn_1) in coefs_with_fns:
        print(coef_1, fn_1)
    print()
    print("Most Informative Malicious Features:")
    for (coef_2, fn_2) in coefs_with_fns_mal:
        print(coef_2, fn_2)
    print()


def benchmark(clf, showTopFeatures=False):
    print('_'*60)
    print("Training: ")
    print(clf)
    t0 = time()
    clf.fit(X_train, train_corpus_target)

    train_time = time() - t0
    print("train time: %0.3fs" % train_time)


    t0 = time()
    pred = clf.predict(X_test)
    test_time = time() - t0
    print("test time: %0.3fs" % test_time)

    score = metrics.accuracy_score(test_corpus_target, pred)
    print("accuracy: %0.3f" % score)

    if hasattr(clf, 'coef_'):
        print("dimensionality: %d" % clf.coef_.shape[1])
        print("density: %f" % density(clf.coef_))
        print()
    print(metrics.classification_report(test_corpus_target, pred,target_names=my_categories))
    print()
    clf_descr = str(clf).split('(')[0]

    print("Predicted values: ")
    print(pred.tolist());
    print()
    print("Real values:")
    print(test_corpus_target)
    print()
    mCount = 0
    for i in test_corpus_target:
        if i == 1:
            mCount+=1
    print("Proportion of malicious trace:")
    print(mCount/len(test_corpus_target))

    if showTopFeatures:
        show_most_informative_features(vectorizer, clf, 10)

    return clf_descr, score, train_time, test_time


results = []
for clf, name in (
        (RidgeClassifier(tol=1e-2, solver="lsqr"), "Ridge Classifier"),
        (Perceptron(n_iter=50), "Perceptron"),
        (PassiveAggressiveClassifier(n_iter=50), "Passive-Aggressive"),
        (KNeighborsClassifier(n_neighbors=10), "kNN"),
        (RandomForestClassifier(n_estimators=100), "Random forest")):
    print('=' * 80)
    print(name)
    results.append(benchmark(clf))






for penalty in ["l2", "l1"]:
    print('=' * 80)
    print("%s penalty" % penalty.upper())
    # Train Liblinear model
    results.append(benchmark(LinearSVC(penalty=penalty, dual=False,
                                       tol=1e-3), showMostInformativeFeatures))

    # Train SGD model
    results.append(benchmark(SGDClassifier(alpha=.0001, n_iter=50,
                                           penalty=penalty), showMostInformativeFeatures))

# Train SGD with Elastic Net penalty
print('=' * 80)
print("Elastic-Net penalty")
results.append(benchmark(SGDClassifier(alpha=.0001, n_iter=50,
                                       penalty="elasticnet")))

# Train NearestCentroid without threshold
print('=' * 80)
print("NearestCentroid (aka Rocchio classifier)")
results.append(benchmark(NearestCentroid()))

# Train sparse Naive Bayes classifiers
print('=' * 80)
print("Naive Bayes")
results.append(benchmark(MultinomialNB(alpha=.01)))
results.append(benchmark(BernoulliNB(alpha=.01)))

print('=' * 80)
print("LinearSVC with L1-based feature selection")
# The smaller C, the stronger the regularization.
# The more regularization, the more sparsity.
results.append(benchmark(Pipeline([
  ('feature_selection', SelectFromModel(LinearSVC(penalty="l1", dual=False,
                                                  tol=1e-3))),
  ('classification', LinearSVC(penalty="l2"))])))


# plotting results

indices = np.arange(len(results))

results = [[x[i] for x in results] for i in range(4)]

clf_names, score, training_time, test_time = results
training_time = np.array(training_time) / np.max(training_time)
test_time = np.array(test_time) / np.max(test_time)

plt.figure(figsize=(12, 8))
plt.title("Score")
plt.barh(indices, score, .2, label="score", color='navy')
plt.barh(indices + .3, training_time, .2, label="training time",
         color='c')
plt.barh(indices + .6, test_time, .2, label="test time", color='darkorange')
plt.yticks(())
plt.legend(loc='best')
plt.subplots_adjust(left=.25)
plt.subplots_adjust(top=.95)
plt.subplots_adjust(bottom=.05)

for i, c in zip(indices, clf_names):
    plt.text(-.3, i, c)

plt.show()
