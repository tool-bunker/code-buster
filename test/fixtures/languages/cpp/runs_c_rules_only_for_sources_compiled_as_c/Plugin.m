#import "Plugin.h"
@implementation Plugin
- (void)release:(void *)value {
  free(value);
}
@end
