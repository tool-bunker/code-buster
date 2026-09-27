useTestRetrieval();
refetchRetrieval();
eval(source);
window.eval(source);
globalThis.eval(source);
new Function(source);
new Function(`return ${source}`);
new Function('return 1');
new Function(
  'value',
  'return value'
);
redis.eval(script);
redis?.eval(script);
page.$eval('#image', (element) => element.complete);
page.$$eval('script', (elements) => elements.length);
function eval(source: string) {}
class Evaluator {
  public eval(source: string): unknown;
  public eval(source: string, mode: string): unknown;
  public eval(source: string, mode?: string) {}
}
interface Evaluation {
  eval(source: string): unknown;
}
// Most eval() calls use this stack frame format.
/* Parse nested eval() calls. */
