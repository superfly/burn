# Burn

Burn is a load testing tool with a shot statistical analysis of:
- Connect time
- TLS Handshake duration
- Request write time
- Response read time

## Usage

```bash
burn -c 10 -d 2s https://localhost:8000/
```

## Output

```
Burning https://localhost:8000/ for 2s

Statistical Analysis:
+-----------------------+----------+----------+----------+----------+---------+----------+----------+----------+
|        Metric         |   p50    |   p75    |   p95    |   p99    |   Min   |   Mean   |   Max    | Std. Dev |
+-----------------------+----------+----------+----------+----------+---------+----------+----------+----------+
| Connect               | 1.264ms  | 1.765ms  | 2.145ms  | 2.187ms  | 107µs   | 1.196ms  | 2.187ms  | 670µs    |
| TLS Handshake         | 40.442ms | 41.825ms | 42.972ms | 43.414ms | 2.012ms | 26.782ms | 43.414ms | 18.32ms  |
| Request fully written | 8µs      | 10µs     | 24µs     | 72µs     | 4µs     | 13µs     | 3.272ms  | 46µs     |
| Response fully read   | 775µs    | 1.618ms  | 3.869ms  | 6.724ms  | 106µs   | 1.285ms  | 48.976ms | 1.795ms  |
+-----------------------+----------+----------+----------+----------+---------+----------+----------+----------+

Meta:
  Requests Count |        33524
  Time spent     | 2.003925859s
  RPS            | 16729.161835
  TLS Resumed    |           13

Ciphers:
ECDHE ECDSA w/ AES_256_GCM_SHA384 => 33

Errors:
0 errors.
```