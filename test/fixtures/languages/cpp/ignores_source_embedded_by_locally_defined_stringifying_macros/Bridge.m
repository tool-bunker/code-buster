#import "Stringify.h"
NSString *bridgeScript(void) {
  static NSString *script = SCRIPT_SOURCE(
    ;(function() {
      if (window.bridge) {
        return;
      }
      for (var index = 0; index < callbacks.length; index++) {
        callbacks[index]();
      }
    })();
  );
  return script;
}
