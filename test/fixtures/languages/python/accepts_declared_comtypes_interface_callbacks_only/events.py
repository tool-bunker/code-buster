class Handler(comtypes.COMObject):
    _com_interfaces_ = [UIA.IEventHandler]
    def HandleEvent(self, sender):
        return 0

class Ordinary:
    _com_interfaces_ = [object]
    def HandleEvent(self, sender):
        return 0
