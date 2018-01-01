x = 1
class bruh():
    def __init__(self):
        self.xy = 0
        pass

    def run(self):
        global x
        self.xy = x
        print(self.xy)

bj = bruh()
bj.run()