import { describe, expect, it } from 'vitest';
import { locationOf, whereText } from './location';

describe('locationOf', () => {
  it('flattens what the server sends, whichever kind the scanner gave', () => {
    expect(locationOf({ code: { file_path: 'src/a.go', start_line: 12, end_line: 14, snippet: 'x := 1' } })).toEqual({ file_path: 'src/a.go', start_line: 12, end_line: 14, snippet: 'x := 1' });
    expect(locationOf({ package: { purl: 'pkg:npm/lodash@4.17.20', component_name: 'lodash', installed_version: '4.17.20', fixed_version: '4.17.21', manifest_path: 'package-lock.json', dependency_path: ['app', 'lodash'] }, image: 'alpine:3.16' }))
      .toMatchObject({ purl: 'pkg:npm/lodash@4.17.20', fixed_version: '4.17.21', manifest_path: 'package-lock.json', dependency_path: ['app', 'lodash'], image: 'alpine:3.16' });
    expect(locationOf({ web: { normalized_url: 'https://shop.example.com/cart', method: 'POST', param: 'qty' } })).toEqual({ url: 'https://shop.example.com/cart', method: 'POST', param: 'qty' });
    expect(locationOf({ resource: { resource_address: 'aws_s3_bucket.data', resource_type: 'aws_s3_bucket' }, code: { file_path: 'infra/s3.tf', start_line: 14 } }))
      .toMatchObject({ resource_address: 'aws_s3_bucket.data', file_path: 'infra/s3.tf' });
  });

  it('passes a flat location through, and survives nothing', () => {
    expect(locationOf({ purl: 'pkg:npm/x@1', file_path: 'a' })).toEqual({ purl: 'pkg:npm/x@1', file_path: 'a' });
    expect(locationOf(undefined)).toEqual({});
    expect(locationOf(null)).toEqual({});
    expect(locationOf('x')).toEqual({});
  });

  it('drops empty values, so a screen shows only what the scanner knew', () => {
    expect(locationOf({ code: { file_path: 'a.go', snippet: '', start_line: 0 } })).toEqual({ file_path: 'a.go' });
  });
});

describe('whereText', () => {
  it('names the package, else the file and line, else the address, the resource, the image', () => {
    expect(whereText({ purl: 'pkg:npm/x@1' })).toBe('pkg:npm/x@1');
    expect(whereText({ component_name: 'x', installed_version: '1' })).toBe('x 1');
    expect(whereText({ file_path: 'a.go', start_line: 4 })).toBe('a.go:4');
    expect(whereText({ url: 'https://x/y', method: 'GET' })).toBe('GET https://x/y');
    expect(whereText({ resource_address: 'aws_s3_bucket.data' })).toBe('aws_s3_bucket.data');
    expect(whereText({ image: 'alpine:3.16' })).toBe('alpine:3.16');
    expect(whereText({})).toBe('');
  });
});
