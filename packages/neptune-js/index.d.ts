/// <reference types="node" />

/**
 * @returns 'hello neon'.
 */
export function hello(): string;

/**
 * Calculate the poseidon hash (t=3).
 * @param input0 is a hex string without '0x' prefix (less than or equal to 32 bytes and even length).
 * @param input1 is a hex string without '0x' prefix (less than or equal to 32 bytes and even length).
 * @returns the result of `poseidon([input0, input1])`, which is a 32 bytes hex string without '0x' prefix.
 * @example ```
 *   const result = poseidon_t3("01", "02"); // OK: '17913732bd28f1e73f4cb7bae1a9949d071ee1ea41784725a47c880c40b9e6fb'
 *   const result = poseidon_t3("1", "2"); // NG: 'internal error in Neon module: fail to convert arguments: OddLength'
 * ```
 */
export function poseidon_t3(input0: string, input1: string): string;
