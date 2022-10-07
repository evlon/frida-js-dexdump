📦
1354 /agent/src/index.js.map
1235 /agent/src/index.js
9524 /agent/src/search.js.map
14911 /agent/src/search.js
✄
{"version":3,"file":"index.js","sourceRoot":"E:/Repos/frida/frida-study/","sources":["agent/src/index.ts"],"names":[],"mappings":"AAAA;;;;IAII;AAEJ,OAAO,EAAC,SAAS,EAAC,MAAM,aAAa,CAAC;AAEtC,SAAS,iBAAiB,CAAC,IAAmB,EAAE,IAAY;IACxD,MAAM,GAAG,GAAG,IAAI,CAAC,GAAG,CAAC,IAAI,CAAC,CAAC;IAC3B,OAAO,CAAC,eAAe,CAAC,KAAK,CAAC,CAAC,OAAO,CAAC,UAAU,KAAK;QAClD,MAAM,SAAS,GAAG,KAAK,CAAC,IAAI,CAAC,GAAG,CAAC,KAAK,CAAC,IAAI,CAAC,CAAA;QAC5C,IAAI,KAAK,CAAC,IAAI,GAAG,IAAI,IAAI,SAAS,GAAG,GAAG,EAAE;YACtC,OAAM;SACT;QACD,IAAI,CAAC,KAAK,CAAC,UAAU,CAAC,UAAU,CAAC,GAAG,CAAC,EAAE;YACnC,OAAO,CAAC,GAAG,CAAC,wCAAwC,GAAG,IAAI,GAAG,GAAG,GAAG,SAAS,CAAC,CAAA;YAC9E,MAAM,CAAC,OAAO,CAAC,KAAK,CAAC,IAAI,EAAE,KAAK,CAAC,IAAI,EAAE,GAAG,GAAG,KAAK,CAAC,UAAU,CAAC,MAAM,CAAC,CAAC,EAAE,CAAC,CAAC,CAAC,CAAA;SAC9E;IAEL,CAAC,CAAC,CAAA;AACN,CAAC;AAGD,GAAG,CAAC,OAAO,GAAG;IACV,UAAU,EAAE,UAAU,OAAO,EAAE,IAAI;QAC/B,MAAM,GAAG,GAAG,IAAI,aAAa,CAAC,OAAO,CAAC,CAAC;QACvC,iBAAiB,CAAC,GAAG,EAAE,IAAI,CAAC,CAAC;QAC7B,OAAO,GAAG,CAAC,aAAa,CAAC,IAAI,CAAC,CAAC;IACnC,CAAC;IACD,SAAS,EAAE,UAAU,gBAAyB;QAC1C,OAAO,SAAS,CAAC,gBAAgB,CAAC,CAAC;IACvC,CAAC;IACD,WAAW,EAAE;QACT,OAAO,CAAC,gBAAgB,EAAE,CAAC,OAAO,CAAC,UAAU,MAAM;QACnD,CAAC,CAAC,CAAA;IACN,CAAC;CAEJ,CAAC;AAEF,OAAO,CAAC,GAAG,CAAC,qBAAqB,IAAI,IAAI,EAAE,wBAAwB,CAAC,CAAA;AACpE,IAAI,MAAM,GAAG,SAAS,CAAC,KAAK,CAAC,CAAC;AAC9B,OAAO,CAAC,GAAG,CAAC,MAAM,CAAC,MAAM,CAAC,CAAA"}
✄
/*
* Author: hluwa <hluwa888@gmail.com>
* HomePage: https://github.com/hluwa
* CreateTime: 2021/6/2
* */
import { searchDex } from "./search.js";
function setReadPermission(base, size) {
    const end = base.add(size);
    Process.enumerateRanges("---").forEach(function (range) {
        const range_end = range.base.add(range.size);
        if (range.base < base || range_end > end) {
            return;
        }
        if (!range.protection.startsWith("r")) {
            console.log("Set read permission for memory range: " + base + "-" + range_end);
            Memory.protect(range.base, range.size, "r" + range.protection.substr(1, 2));
        }
    });
}
rpc.exports = {
    memorydump: function (address, size) {
        const ptr = new NativePointer(address);
        setReadPermission(ptr, size);
        return ptr.readByteArray(size);
    },
    searchdex: function (enableDeepSearch) {
        return searchDex(enableDeepSearch);
    },
    stopthreads: function () {
        Process.enumerateThreads().forEach(function (thread) {
        });
    },
};
console.log(`------------------${new Date()}----------------------`);
let ranges = searchDex(false);
console.log(ranges.length);
✄
{"version":3,"file":"search.js","sourceRoot":"E:/Repos/frida/frida-study/","sources":["agent/src/search.ts"],"names":[],"mappings":"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"}
✄
/*
* Author: hluwa <hluwa888@gmail.com>
* HomePage: https://github.com/hluwa
* CreateTime: 2021/6/3
* */
/*
map_list
名称	格式	说明
size	uint	列表的大小（以条目数表示）
list	map_item[size]	列表的元素



map_item 格式
名称	格式	说明
type	ushort	项的类型；见下表
unused	ushort	（未使用）
size	uint	在指定偏移量处找到的项数量
offset	uint	从文件开头到相关项的偏移量
*/
/*
类型代码
项类型	常量	值	项大小（以字节为单位）
header_item	TYPE_HEADER_ITEM	0x0000	0x70
string_id_item	TYPE_STRING_ID_ITEM	0x0001	0x04
type_id_item	TYPE_TYPE_ID_ITEM	0x0002	0x04
proto_id_item	TYPE_PROTO_ID_ITEM	0x0003	0x0c
field_id_item	TYPE_FIELD_ID_ITEM	0x0004	0x08
method_id_item	TYPE_METHOD_ID_ITEM	0x0005	0x08
class_def_item	TYPE_CLASS_DEF_ITEM	0x0006	0x20
call_site_id_item	TYPE_CALL_SITE_ID_ITEM	0x0007	0x04
method_handle_item	TYPE_METHOD_HANDLE_ITEM	0x0008	0x08
map_list	TYPE_MAP_LIST	0x1000	4 + (item.size * 12)
type_list	TYPE_TYPE_LIST	0x1001	4 + (item.size * 2)
annotation_set_ref_list	TYPE_ANNOTATION_SET_REF_LIST	0x1002	4 + (item.size * 4)
annotation_set_item	TYPE_ANNOTATION_SET_ITEM	0x1003	4 + (item.size * 4)
class_data_item	TYPE_CLASS_DATA_ITEM	0x2000	隐式；必须解析
code_item	TYPE_CODE_ITEM	0x2001	隐式；必须解析
string_data_item	TYPE_STRING_DATA_ITEM	0x2002	隐式；必须解析
debug_info_item	TYPE_DEBUG_INFO_ITEM	0x2003	隐式；必须解析
annotation_item	TYPE_ANNOTATION_ITEM	0x2004	隐式；必须解析
encoded_array_item	TYPE_ENCODED_ARRAY_ITEM	0x2005	隐式；必须解析
annotations_directory_item	TYPE_ANNOTATIONS_DIRECTORY_ITEM	0x2006	隐式；必须解析
hiddenapi_class_data_item	TYPE_HIDDENAPI_CLASS_DATA_ITEM	0xF000	隐式；必须解析
*/
// 
function verify_by_maps_old(dexptr, mapsptr, range_base, range_end) {
    const maps_offset = dexptr.add(0x34).readUInt();
    const maps_size = mapsptr.readUInt();
    for (let i = 0; i < maps_size; i++) {
        const item_type = mapsptr.add(4 + i * 0xC).readU16();
        if (item_type === 4096) {
            const map_offset = mapsptr.add(4 + i * 0xC + 8).readUInt();
            if (maps_offset === map_offset) {
                return true;
            }
        }
    }
    return false;
}
function verify_by_maps(dexptr, mapsptr, range_base, range_end) {
    const maps_size = mapsptr.readUInt();
    //看看每一个map_item type 是不是正确
    let rightTypeList = [
        0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008,
        0x1000, 0x1001, 0x1002, 0x1003,
        0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
        0xF000
    ];
    let processed_type = new Map();
    let unknown_type = new Map();
    let mustOk = false;
    for (let i = 0; i < maps_size; i++) {
        // ptr is map_item[] begin addr
        let ptr = mapsptr.add(4 + i * 0xC);
        const item_type = ptr.readU16();
        if (rightTypeList.indexOf(item_type) == -1) {
            unknown_type.set(item_type, 1);
            //警告一下
            send(`[warn] map item type error: idx:${i} type:0x${item_type.toString(16).padStart(4, '0')}  dexptr:${dexptr}`);
        }
        else {
            let val = processed_type.get(item_type) || 0;
            val++;
            processed_type.set(item_type, val);
            if (val > 1) {
                send(`[warn] map item type repeet: times:${val} idx:${i} type:0x${item_type.toString(16).padStart(4, '0')} dexptr:${dexptr}`);
            }
        }
        let map_item_size = ptr.add(4).readU32();
        let map_item_offset = ptr.add(8).readU32();
        const map_item_offset_addr = dexptr.add(map_item_offset);
        //特殊情况，size == 0 offset must == 0
        if (map_item_size === 0 && map_item_offset !== 0) {
            return false;
        }
        //地址超出也不行
        if (map_item_offset_addr < range_base || map_item_offset_addr > range_end) {
            send(`[bad dex skip] map item type error: idx:${i} addr out of range:0x${map_item_offset.toString(16).padStart(4, '0')}`);
            return false;
        }
        if (item_type === 0x1000) {
            //map_off	uint	从文件开头到映射项的偏移量。该偏移量（必须为非零值）应该是到 data 区段的偏移量，而数据应采用下文中“map_list”指定的格式。
            const map_offset = map_item_offset;
            const header_map_offset = dexptr.add(0x34).readUInt();
            if (header_map_offset !== map_offset) {
                send(`[bad dex skip] map item header_map_offset(${header_map_offset}) !== map_offset(${map_offset}): idx:${i} `);
                return false;
            }
            else {
                mustOk = true;
            }
        }
        else if (item_type === 0x0001) {
            //type_ids  从文件开头到类型标识符列表的偏移量；如果 type_ids_size == 0（不可否认是一种奇怪的极端情况），则该值为 0。该偏移量（如果为非零值）应该是到 type_ids 区段开头的偏移量。
            const header_string_id_size = dexptr.add(0x38).readUInt();
            const header_string_id_offset = dexptr.add(0x38 + 4).readUInt();
            if (header_string_id_size !== map_item_size) {
                send(`[bad dex skip] map item header_string_id_size(${header_string_id_size}) !== map_item_size(${map_item_size}): idx:${i} `);
                return false;
            }
            if (header_string_id_offset !== map_item_offset) {
                send(`[bad dex skip] map item header_string_id_offset(${header_string_id_offset}) !== map_item_offset(${map_item_offset}): idx:${i} `);
                return false;
            }
        }
        else if (item_type === 0x0002) {
            //type_ids  从文件开头到类型标识符列表的偏移量；如果 type_ids_size == 0（不可否认是一种奇怪的极端情况），则该值为 0。该偏移量（如果为非零值）应该是到 type_ids 区段开头的偏移量。
            const header_type_ids_size = dexptr.add(0x3C).readUInt();
            const header_type_ids_offset = dexptr.add(0x3C + 4).readUInt();
            //类型标识符列表中的元素数量，最多为 65535
            if (map_item_size > 65535) {
                return false;
            }
            if (header_type_ids_size !== map_item_size) {
                send(`[bad dex skip] map item header_type_ids_size(${header_type_ids_size}) !== map_item_size(${map_item_size}): idx:${i} `);
                return false;
            }
            if (header_type_ids_offset !== map_item_offset) {
                send(`[bad dex skip] map item header_type_ids_offset(${header_type_ids_offset}) !== map_item_offset(${map_item_offset}): idx:${i} `);
                return false;
            }
        }
        else {
            // nop
            continue;
        }
    }
    // 已知的，怎么也的多于未知的吧。
    return mustOk && processed_type.keys.length > unknown_type.keys.length;
}
function get_dex_real_size(dexptr, range_base, range_end) {
    const dex_size = dexptr.add(0x20).readUInt();
    const maps_address = get_maps_address(dexptr, range_base, range_end);
    if (!maps_address) {
        return dex_size;
    }
    const maps_end = get_maps_end(maps_address, range_base, range_end);
    if (!maps_end) {
        return dex_size;
    }
    return maps_end.sub(dexptr).toInt32();
}
function get_maps_address(dexptr, range_base, range_end) {
    //+0x34 是 map_off ，也就是 map 段的偏移位置，一般情况下 map 段都是在 DEX 文件的最末尾，与 file_size 同理
    const maps_offset = dexptr.add(0x34).readUInt();
    if (maps_offset === 0) {
        return null;
    }
    const maps_address = dexptr.add(maps_offset);
    //必须再Range的内存范围内，不在就不是
    if (maps_address < range_base || maps_address > range_end) {
        return null;
    }
    return maps_address;
}
function get_maps_end(maps, range_base, range_end) {
    const maps_size = maps.readUInt();
    // send(`get_maps_end maps_size:${maps_size}`)
    if (maps_size < 2 || maps_size > 50) {
        return null;
    }
    const maps_end = maps.add(maps_size * 0xC + 4);
    if (maps_end < range_base || maps_end > range_end) {
        return null;
    }
    return maps_end;
}
function verify(dexptr, range, enable_verify_maps) {
    if (range != null) {
        var range_end = range.base.add(range.size);
        // verify header_size header 结构放不下，跳过
        if (dexptr.add(0x70) > range_end) {
            return false;
        }
        if (enable_verify_maps) {
            var maps_address = get_maps_address(dexptr, range.base, range_end);
            if (!maps_address) {
                return false;
            }
            var maps_end = get_maps_end(maps_address, range.base, range_end);
            if (!maps_end) {
                return false;
            }
            return verify_by_maps(dexptr, maps_address, range.base, range_end);
        }
        else {
            // TODO: 读取头的大小，如果这里读出来的都是正确的，后面为啥还修复？ 
            return dexptr.add(0x3C).readUInt() === 0x70;
        }
    }
    return false;
}
function verify_ids_off(dexptr, dex_size) {
    const string_ids_off = dexptr.add(0x3C).readUInt();
    const type_ids_off = dexptr.add(0x44).readUInt();
    const proto_ids_off = dexptr.add(0x4C).readUInt();
    const field_ids_off = dexptr.add(0x54).readUInt();
    const method_ids_off = dexptr.add(0x5C).readUInt();
    //考虑特殊情况，添加一下
    // xxx_size == 0（不可否认是一种奇怪的极端情况），则该值为 0
    return string_ids_off < dex_size && (string_ids_off >= 0x70 || string_ids_off === 0)
        && type_ids_off < dex_size && (type_ids_off >= 0x70 || type_ids_off === 0)
        && proto_ids_off < dex_size && (proto_ids_off >= 0x70 || proto_ids_off === 0)
        && field_ids_off < dex_size && (field_ids_off >= 0x70 || field_ids_off === 0)
        && method_ids_off < dex_size && (method_ids_off >= 0x70 || method_ids_off === 0);
}
export function searchDex(deepSearch) {
    const result = [];
    //Process.enumerateRanges('r--') 这是用于遍历当前进程中所有可以读的内存段，毕竟不能读的内存区域是不能被 VM 执行的 (Native 可以)。想必不难理解。
    Process.enumerateRanges('r--').forEach(function (range) {
        try {
            //DEX\\n3??0  搜索 64 65 78 0a 30 ?? ?? 00
            Memory.scanSync(range.base, range.size, "64 65 78 0a 30 ?? ?? 00").forEach(function (match) {
                //跳过系统的
                if (range.file && range.file.path
                    && (range.file.path.startsWith("/data/dalvik-cache/") ||
                        range.file.path.startsWith("/system/"))) {
                    return;
                }
                // send("search normal dex\\n begin header...")
                // 正常的，一般也不用检查别的了， 但是如果对方内存里面放点这个东西呢？那就乱了。
                // send(`-----------begin range ${match.address} --------------`)
                if (verify(match.address, range, false)) {
                    const dex_size = get_dex_real_size(match.address, range.base, range.base.add(range.size));
                    send(`found normal dex\\n begin header, addr:${match.address}, size:${dex_size}`);
                    result.push({
                        "addr": match.address,
                        "size": dex_size
                    });
                    const max_size = range.size - match.address.sub(range.base).toInt32();
                    //如果这里面，Range没有占满，可能考虑有重分布，全部弄出来保险点？
                    if (deepSearch && max_size != dex_size) {
                        result.push({
                            "addr": match.address,
                            "size": max_size
                        });
                    }
                }
            });
            if (deepSearch) {
                //先查找具有 headersize 的内存，然后减去 0x3c 得到DEX头的位置。  应对加固的时候，DEX不在开始的情况
                Memory.scanSync(range.base, range.size, "70 00 00 00 78 56 34 12")
                    .concat(Memory.scanSync(range.base, range.size, "70 00 00 00 12 34 56 78")).forEach(function (match) {
                    const dex_base = match.address.sub(0x3C);
                    if (dex_base < range.base) {
                        //前面没有 0x3c 的大小，不是
                        return;
                    }
                    //如果有 uchar[8] magic <comment="Magic value">; 并且正确
                    // TODO: 如果这里也没有呢？被修改了呢？程序还可以运行吗？
                    if (dex_base.readCString(4) != "dex\n" && verify(dex_base, range, true)) {
                        //计算真实大小
                        const real_dex_size = get_dex_real_size(dex_base, range.base, range.base.add(range.size));
                        if (!verify_ids_off(dex_base, real_dex_size)) {
                            return;
                        }
                        result.push({
                            "addr": dex_base,
                            "size": real_dex_size
                        });
                        const max_size = range.size - dex_base.sub(range.base).toInt32();
                        send(`DeepSearch found 'not dex\\n begin' header. , addr:${range.base}, size:${real_dex_size}`);
                        if (max_size != real_dex_size) {
                            result.push({
                                "addr": dex_base,
                                "size": max_size
                            });
                        }
                    }
                });
            }
            else {
                if (range.base.readCString(4) != "dex\n" && verify(range.base, range, true)) {
                    const real_dex_size = get_dex_real_size(range.base, range.base, range.base.add(range.size));
                    send(`found 'not dex\\n begin' header. , addr:${range.base}, size:${real_dex_size}`);
                    result.push({
                        "addr": range.base,
                        "size": real_dex_size
                    });
                }
            }
        }
        catch (e) {
            console.log(e);
        }
    });
    return result;
}