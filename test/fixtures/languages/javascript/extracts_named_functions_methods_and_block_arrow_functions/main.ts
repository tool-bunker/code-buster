function parse(value: string) {
  if (value) return value;
  return '';
}
class Service {
  async execute<T>(value: T): Promise<T> {
    return value;
  }
}
const validate = (value: string): boolean => {
  return value.length > 0;
};
const fake = "function ignored() { return false; }";
