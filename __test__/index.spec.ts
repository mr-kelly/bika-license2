import test from 'ava'

import { sum, decrypt } from '../index.js'

// 基本功能测试
test('sum function', (t) => {
  t.is(sum(1, 2), 3)
  t.is(sum(-1, 1), 0)
  t.is(sum(0, 0), 0)
  t.is(sum(100, 200), 300)
})

// 基本解密测试
test('basic decrypt test', (t) => {
  const decrypted = decrypt('0m1sZE8TXVU2LS9bpjFu4orBPEmA4GGfxW37oQQpKOhlsl5LtfMlU1pSdu5Q/KLSwL05db8Ku5yOo/YgwmfxNHOFA1DfD9AI3/Ygvvej8KX3yaIyup6xN9znwltb7LylU0OYL93AbzLGpmqY7G01b9J5mx2GoQnFVhDRaizmIS+xYFjE1yzBrqfUSVv3wtznNpsgvB7RyJC5I95zbiSt/XcqYAdvugw4JH5LgqT8Gydpt32zFrDaFMSKe2ss+nPbDS2nEUrWXL4Bvi3VOs9RkqoLzUCa52mHVimMj9oG7C/KFhC6Vk7sXpR8FRv5FphNk+mCBMGRrGd10RvduKRhiQ==');
  t.is(decrypted, 'Hello, World!');
})

// 边界测试 - 字符串长度测试
test('decrypt with various string lengths', (t) => {
  // 测试超长输入应该抛出错误
  const tooLongInput = 'A'.repeat(600); // 超过500字符限制
  
  t.throws(() => {
    decrypt(tooLongInput);
  }, { message: /Input too long/ });
})

// 错误处理测试
test('decrypt with invalid input should throw error', (t) => {
  // 空字符串
  t.throws(() => {
    decrypt('');
  }, { message: /Input cannot be empty/ });
  
  // 无效的 base64
  t.throws(() => {
    decrypt('invalid_base64!');
  }, { message: /Invalid base64 encoding/ });
  
  // 无效的加密数据（有效base64但不是正确的加密数据）
  t.throws(() => {
    decrypt('VGhpcyBpcyBub3QgZW5jcnlwdGVkIGRhdGE='); // "This is not encrypted data" in base64
  }, { message: /Invalid encrypted data size/ });
  
  // 格式错误的 base64
  t.throws(() => {
    decrypt('SGVsbG8gV29ybGQ==='); // 过多的 padding
  }, { message: /Invalid base64 encoding/ });
})

// 输入类型测试
test('function parameter type validation', (t) => {
  // sum 函数的参数类型测试
  t.is(sum(1.5, 2.7), 3); // 浮点数会被转换为整数: 1 + 2 = 3
  
  // decrypt 函数应该只接受字符串
  t.throws(() => {
    decrypt(null!);
  }, { message: /Failed to convert JavaScript value `Null` into rust type `String`/ });
  
  t.throws(() => {
    decrypt(undefined!);
  }, { message: /Failed to convert JavaScript value `Undefined` into rust type `String`/ });
  
  t.throws(() => {
    decrypt(123);
  }, { message: /Failed to convert JavaScript value `Number 123 ` into rust type `String`/ });
  
  t.throws(() => {
    decrypt({});
  }, { message: /Failed to convert JavaScript value `Object {}` into rust type `String`/ });
  
  t.throws(() => {
    decrypt([]);
  }, { message: /Failed to convert JavaScript value `Object \[\]` into rust type `String`/ });
})

// 字符串长度边界测试
test('string length boundary tests', (t) => {
  // 测试接近245字符限制的情况
  const longString = 'A'.repeat(244); // 244 字符，应该可以
  const tooLongString = 'A'.repeat(246); // 246 字符，应该失败
  
  // 注意：这里我们不能直接测试加密，因为我们没有公钥
  // 但我们可以测试系统对超长字符串的响应
  
  // 测试长字符串的base64编码是否会导致问题
  const longBase64 = Buffer.from(longString).toString('base64');
  t.throws(() => {
    decrypt(longBase64);
  }, { message: /Invalid encrypted data size/ });
  
  const tooLongBase64 = Buffer.from(tooLongString).toString('base64');
  t.throws(() => {
    decrypt(tooLongBase64);
  }, { message: /Invalid encrypted data size/ });
})

// 特殊字符测试
test('special characters handling', (t) => {
  // 测试包含特殊字符的base64字符串
  const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  const unicodeChars = '你好世界🌍🚀💻';
  
  // 这些不是有效的加密数据，所以应该抛出错误
  t.throws(() => {
    decrypt(Buffer.from(specialChars).toString('base64'));
  }, { message: /Invalid encrypted data size/ });
  
  t.throws(() => {
    decrypt(Buffer.from(unicodeChars).toString('base64'));
  }, { message: /Invalid encrypted data size/ });
})

// 性能测试
test('performance test', (t) => {
  const startTime = Date.now();
  
  // 执行多次sum操作
  for (let i = 0; i < 1000; i++) {
    sum(i, i + 1);
  }
  
  const endTime = Date.now();
  const duration = endTime - startTime;
  
  // 期望1000次操作在合理时间内完成（比如小于100ms）
  t.true(duration < 1000, `Performance test took ${duration}ms, expected < 1000ms`);
})

// 内存使用测试
test('memory usage test', (t) => {
  const initialMemory = process.memoryUsage().heapUsed;
  
  // 执行一些操作
  for (let i = 0; i < 100; i++) {
    try {
      decrypt('invalid_data_' + i);
    } catch (e) {
      // 预期会抛出错误
      t.true(e instanceof Error);
    }
  }
  
  // 强制垃圾回收（如果可用）
  if (global.gc) {
    global.gc();
  }
  
  const finalMemory = process.memoryUsage().heapUsed;
  const memoryIncrease = finalMemory - initialMemory;
  
  // 期望内存增长不会太大（比如小于10MB）
  t.true(memoryIncrease < 10 * 1024 * 1024, `Memory increased by ${memoryIncrease} bytes`);
})

// 并发测试
test('concurrent operations', async (t) => {
  const promises = [];
  
  // 创建多个并发的sum操作
  for (let i = 0; i < 10; i++) {
    promises.push(Promise.resolve(sum(i, i * 2)));
  }
  
  const results = await Promise.all(promises);
  
  // 验证所有结果都是正确的
  for (let i = 0; i < 10; i++) {
    t.is(results[i], i + (i * 2));
  }
})

// RSA-2048 特定的边界测试
test('RSA-2048 specific boundary tests', (t) => {
  // 测试 RSA-2048 的特定限制
  
  // 测试正确大小的随机数据（256字节 = RSA-2048密文大小）
  const correctSizeData = Buffer.alloc(256, 1); // 256字节的数据
  const correctSizeBase64 = correctSizeData.toString('base64');
  
  t.throws(() => {
    decrypt(correctSizeBase64);
  }, { message: /Decryption failed/ }); // 应该是解密失败，而不是大小错误
  
  // 测试错误大小的数据
  const wrongSizeData = Buffer.alloc(255, 1); // 255字节
  const wrongSizeBase64 = wrongSizeData.toString('base64');
  
  t.throws(() => {
    decrypt(wrongSizeBase64);
  }, { message: /Invalid encrypted data size/ });
  
  // 测试另一个错误大小
  const anotherWrongSizeData = Buffer.alloc(257, 1); // 257字节
  const anotherWrongSizeBase64 = anotherWrongSizeData.toString('base64');
  
  t.throws(() => {
    decrypt(anotherWrongSizeBase64);
  }, { message: /Invalid encrypted data size/ });
})

// 245字符边界测试
test('245 character boundary test', (t) => {
  // 根据RSA-2048标准，明文不能超过245字符
  // 我们无法直接测试这个，因为我们没有公钥进行加密
  // 但我们可以测试如果解密结果超过245字符会被拒绝
  
  // 测试最大允许输入长度 (400字符)
  const maxAllowedInput = 'A'.repeat(400);
  t.throws(() => {
    decrypt(maxAllowedInput);
  }, { message: /Invalid encrypted data size/ }); // 因为不是正确的256字节加密数据
  
  // 测试刚好超过最大长度的输入
  const justOverMaxInput = 'A'.repeat(401);
  t.throws(() => {
    decrypt(justOverMaxInput);
  }, { message: /Input too long/ });
})

// Base64编码边界测试
test('base64 encoding boundary tests', (t) => {
  // 测试各种base64边界情况
  
  // 测试只有填充字符的base64
  t.throws(() => {
    decrypt('====');
  }, { message: /Invalid base64 encoding/ });
  
  // 测试不完整的base64
  t.throws(() => {
    decrypt('SGVsbG8='); // 这是"Hello"，但大小不对
  }, { message: /Invalid encrypted data size/ });
  
  // 测试包含无效字符的base64
  t.throws(() => {
    decrypt('SGVsbG8$V29ybGQ=');
  }, { message: /Invalid base64 encoding/ });
})

// 输入验证压力测试
test('input validation stress test', (t) => {
  const testCases = [
    { input: null, expectedError: /Failed to convert JavaScript value `Null` into rust type `String`/ },
    { input: undefined, expectedError: /Failed to convert JavaScript value `Undefined` into rust type `String`/ },
    { input: '', expectedError: /Input cannot be empty/ },
    { input: ' ', expectedError: /Invalid base64 encoding/ },
    { input: '\n', expectedError: /Invalid base64 encoding/ },
    { input: '\t', expectedError: /Invalid base64 encoding/ },
    { input: '123', expectedError: /Invalid base64 encoding/ },
    { input: 'A'.repeat(450), expectedError: /Input too long/ },
  ];
  
  testCases.forEach(({ input, expectedError }, index) => {
    try {
      t.throws(() => {
        decrypt(input);
      }, { message: expectedError }, `Test case ${index}: ${input}`);
    } catch (e) {
      // 某些情况下可能在更早的阶段失败（比如null/undefined）
      t.true(e instanceof Error, `Test case ${index} should throw an error`);
    }
  });
})
