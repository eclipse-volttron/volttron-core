class MyHelperClass:

    def __init__(self):
        self.inside = "inside"
        self.outside = "outside"


class SecondaryClass(MyHelperClass):

    def __init__(self):
        super().__init__()
        self.secondary_class = "Yup"


class ThirdClass(MyHelperClass):

    def __init__(self):
        super().__init__()
        self.third_class = "Nope"
