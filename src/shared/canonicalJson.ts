export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

function isPlainObject(value: object): boolean {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function serialize(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Canonical JSON only supports finite numbers.');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const items: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) throw new TypeError('Canonical JSON does not support sparse arrays.');
      items.push(serialize(value[index]));
    }
    return `[${items.join(',')}]`;
  }
  if (typeof value === 'object') {
    if (!isPlainObject(value) || Object.getOwnPropertySymbols(value).length > 0) {
      throw new TypeError('Canonical JSON only supports plain JSON objects.');
    }
    const entries = Object.entries(value).sort(([left], [right]) => {
      if (left < right) return -1;
      if (left > right) return 1;
      return 0;
    });
    return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${serialize(child)}`).join(',')}}`;
  }
  throw new TypeError('Canonical JSON received an unsupported value.');
}

export function canonicalJson(value: unknown): string {
  return serialize(value);
}
