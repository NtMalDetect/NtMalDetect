from sklearn.externals import joblib

clf_MultiNB = joblib.load('./pickles/classifier_MultiNB.pkl')
clf_LSVC = joblib.load('./pickles/classifier_Linear_SVC.pkl')
vectorizer = joblib.load('./pickles/vectorizer.pkl')


def classify(input, harsh):
    """
    :param input: a string of system calls separated by spaces.
    :param harsh: a boolean value representing whether or not the classifier
    should be more careful in classifying a system call trace to be malicious or not.
    :return: 0 or 1. 0 will mean that it's a benign program. 1 will mean that it is malicious.
    """
    predict_obj = Predict_Malare(input, harsh, clf_MultiNB, clf_LSVC)
    print(predict_obj.run())


class Predict_Malare():
    def __init__(self, input, harsh, clf1, clf2):
        self._input = []
        self._input.append(input)  # the long string of system calls
        self._harsh = harsh  # AND or OR operator to determine if it's malware
        self._clf1 = clf1  # first classifier used
        self._clf2 = clf2  # second classifier used
        self._pred_clf_1 = 0  # prediction of the first classifier
        self._pred_clf_2 = 0  # prediction of the second classifier
        self._vectorized_input = []  # vectorized input string
        
    def vectorizer(self):
        """ Vectorize input """
        self._vectorized_input = vectorizer.transform(self._input)
        
    def clf1_predict(self):
        """ Predict using first classifier """
        self._pred_clf_1 = self._clf1.predict(self._vectorized_input)[0]

    def clf2_predict(self):
        """ Predict using second classifier """
        self._pred_clf_2 = self._clf2.predict(self._vectorized_input)[0]

    def run(self):
        self.vectorizer()
        self.clf1_predict()
        self.clf2_predict()
        if self._harsh:
            if self._pred_clf_1 == 1 and self._pred_clf_2 == 1:
                return 1
            else:
                return 0
        else:
            if self._pred_clf_1 == 1 or self._pred_clf_2 == 1:
                return 1
            else:
                return 0
