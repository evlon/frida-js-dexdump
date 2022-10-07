export class AndroidApi{


    private static func_Sleep: AnyFunction;
    static usleep(dwMilliseconds: number): void {
        if (this.func_Sleep == null) {
            let address = Module.findExportByName("libandroid_runtime.so", "usleep");
            this.func_Sleep = new NativeFunction(address!, "void", ["int"]);
        }
        return this.func_Sleep(dwMilliseconds);
    } 
    
    
    // private static func_EVP_md5: AnyFunction;
    // static md5(dwMilliseconds: number): void {
    //     if (this.func_EVP_md5 == null) {
    //         let address = Module.findExportByName("libcrypto.so", "EVP_md5");
    //         this.func_EVP_md5 = new NativeFunction(address!, "void", ["int"]);
    //     }
    //     return this.func_EVP_md5(dwMilliseconds);
    // }
} 
// let libcrypto = Module.load("libcrypto.so");
// console.log(libcrypto);