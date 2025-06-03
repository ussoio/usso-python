class instance_method:
    def __init__(self, func):
        self.func = func

    def __get__(self, instance, owner):
        def wrapper(*args, **kwargs):
            if instance is not None:
                return self.func(instance, *args, **kwargs)
            else:
                return self.func(owner(), *args, **kwargs)

        return wrapper
