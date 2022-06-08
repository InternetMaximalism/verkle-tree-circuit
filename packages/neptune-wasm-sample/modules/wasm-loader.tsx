import dynamic from "next/dynamic";

export const WasmComponent = dynamic({
  loader: async () => {
    const wasmModule = await import("neptune-wasm");
    const result = wasmModule.greet("wasm");
    console.log("result", result);
    return () => <div>Adding two numbers: {result}</div>;
  },
});
