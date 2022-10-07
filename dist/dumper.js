import crypt from 'crypto';
import path from 'path';
import fs from 'fs';
function getErrorMessage(e) {
    let msg = e;
    if (typeof e === "string") {
        msg = e.toUpperCase(); // works, `e` narrowed to string
    }
    else if (e instanceof Error) {
        msg = e.message; // works, `e` narrowed to Error
    }
    return { msg, err: e };
}
export class Dumper {
    rpc;
    constructor(rpc) {
        this.rpc = rpc;
    }
    async dump(outputDir, deepSearch = false) {
        // let options = this._options;
        console.log("[+] Searching...");
        let startTime = new Date().valueOf();
        //获取所有的ranges (后面的！告诉编译器忽略错误)
        let ranges = await this.rpc.searchdex(deepSearch);
        let endTime = new Date().valueOf();
        console.log(`[*] Successful found ${ranges.length} dex, used ${(endTime - startTime) / 1000} time.`);
        console.log(`[+] Starting dump to '${outputDir}'...`);
        let dexMd5Map = new Map();
        let classIndex = 1;
        for (const range of ranges) {
            try {
                let dexBytes = await this.rpc.memorydump(range.addr, range.size.valueOf());
                let dexBytesBuffer = Buffer.from(dexBytes);
                //去掉重复的
                let md5sign = crypt.createHash('md5').update(dexBytesBuffer).digest('hex');
                if (dexMd5Map.has(md5sign)) {
                    continue;
                }
                dexMd5Map.set(md5sign, true);
                //修复 dex header
                dexBytesBuffer = this.fixDexHeader(dexBytesBuffer);
                let outputDexPath = path.join(outputDir, `classes${classIndex != 1 ? classIndex : ''}.dex`);
                fs.writeFileSync(outputDexPath, dexBytesBuffer);
                console.log(`[+] DexMd5=${md5sign}, SavePath=${outputDexPath}, DexSize=${range.size.valueOf().toString(16)}`);
                classIndex += 1;
            }
            catch (e) {
                console.warn(getErrorMessage(e).msg);
                continue;
            }
        }
        console.log("[*] All done...");
    }
    /*
  struct header_item {
      uchar[8] magic <comment="Magic value">;
      uint checksum <format=hex, comment="Alder32 checksum of rest of file">;
      uchar[20] signature <comment="SHA-1 signature of rest of file">;
      uint file_size <comment="File size in bytes">;
      uint header_size <comment="Header size in bytes">;
      uint endian_tag <format=hex, comment="Endianness tag">;
      uint link_size <comment="Size of link section">;
      uint link_off <comment="File offset of link section">;
      uint map_off <comment="File offset of map list">;
      uint string_ids_size <comment="Count of strings in the string ID list">;
      uint string_ids_off <comment="File offset of string ID list">;
      uint type_ids_size <comment="Count of types in the type ID list">;
      uint type_ids_off <comment="File offset of type ID list">;
      uint proto_ids_size <comment="Count of items in the method prototype ID list">;
      uint proto_ids_off <comment="File offset of method prototype ID list">;
      uint field_ids_size <comment="Count of items in the field ID list">;
      uint field_ids_off <comment="File offset of field ID list">;
      uint method_ids_size <comment="Count of items in the method ID list">;
      uint method_ids_off <comment="File offset of method ID list">;
      uint class_defs_size <comment="Count of items in the class definitions list">;
      uint class_defs_off <comment="File offset of class definitions list">;
      uint data_size <comment="Size of data section in bytes">;
      uint data_off <comment="File offset of data section">;
  };
  
  https://source.android.google.cn/docs/core/dalvik/dex-format#header-item
  
    */
    fixDexHeader(buffer) {
        let dex_size = buffer.byteLength;
        // if dex_bytes[:4] != b"dex\n":
        // dex_bytes = b"dex\n035\x00" + dex_bytes[8:]
        if (buffer.toString('ascii', 0, 4) !== "dex\n") {
            buffer.write("dex\n", 'ascii');
            // dex_bytes = b"dex\n035\x00" + dex_bytes[8:]
        }
        // if dex_size >= 0x24:
        // dex_bytes = dex_bytes[:0x20] + struct.Struct("<I").pack(dex_size) + dex_bytes[0x24:]
        if (buffer.length >= 0x24) {
            let val = buffer.readUint32LE(0x20);
            if (val == buffer.length) {
                console.log(`[*] fix header: skip fix header.file_size. (${val})`);
            }
            else {
                console.log(`[*] fix header: fix header.file_size. (${val} => ${buffer.length})`);
                buffer.writeUInt32LE(buffer.length, 0x20);
            }
        }
        if (buffer.length >= 0x28) {
            let val = buffer.readUint32LE(0x24);
            if (val == 0x70) {
                console.log(`[*] fix header: skip fix header.header_size. (0x${val.toString(16)})`);
            }
            else {
                console.log(`[*] fix header: fix header.header_size. (${val.toString(16)} => 0x70)`);
                buffer.writeUInt32LE(0x70, 0x24);
            }
        }
        if (buffer.length >= 0x2C && (["\x78\x56\x34\x12", "\x12\x34\x56\x78"].indexOf(buffer.toString('ascii', 0x28, 0x2c)) == -1)) {
            buffer.write("\x78\x56\x34\x12", 0x28, "ascii");
        }
        return buffer;
    }
}
//# sourceMappingURL=dumper.js.map