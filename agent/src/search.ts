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

function verify_by_maps_old(dexptr: NativePointer, mapsptr: NativePointer, range_base: NativePointer, range_end: NativePointer): boolean {
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

function verify_by_maps(dexptr: NativePointer, mapsptr: NativePointer, range_base: NativePointer, range_end: NativePointer): boolean {
    
    const maps_size = mapsptr.readUInt();
    //看看每一个map_item type 是不是正确
    let rightTypeList = [
            0x0000,0x0001,0x0002,0x0003,0x0004,0x0005,0x0006,0x0007,0x0008,
            0x1000,0x1001,0x1002,0x1003,
            0x2000,0x2001,0x2002,0x2003,0x2004,0x2005,0x2006,
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
            unknown_type.set(item_type,1);
            //警告一下
            send(`[warn] map item type error: idx:${i} type:0x${item_type.toString(16).padStart(4, '0')}  dexptr:${dexptr}`);
        }
        else{
            let val = processed_type.get(item_type) || 0;
            val ++;
            processed_type.set(item_type,val)
            if(val > 1){
                send(`[warn] map item type repeet: times:${val} idx:${i} type:0x${item_type.toString(16).padStart(4, '0')} dexptr:${dexptr}`);
            }
        }
        let map_item_size = ptr.add(4).readU32();
        let map_item_offset = ptr.add(8).readU32();
        const map_item_offset_addr = dexptr.add(map_item_offset)
        
        //特殊情况，size == 0 offset must == 0
        if(map_item_size === 0 && map_item_offset !==0){
            return false;
        }
        //地址超出也不行
        if (map_item_offset_addr < range_base || map_item_offset_addr > range_end) {
            send(`[bad dex skip] map item type error: idx:${i} addr out of range:0x${map_item_offset.toString(16).padStart(4,'0')}`)
            return false;
        }

        
        if (item_type === 0x1000) {
            //map_off	uint	从文件开头到映射项的偏移量。该偏移量（必须为非零值）应该是到 data 区段的偏移量，而数据应采用下文中“map_list”指定的格式。
            const map_offset =map_item_offset;
            const header_map_offset = dexptr.add(0x34).readUInt();
            if (header_map_offset !== map_offset) {
                send(`[bad dex skip] map item header_map_offset(${header_map_offset}) !== map_offset(${map_offset}): idx:${i} `)
                 return false;
            }
            else{
                mustOk = true;
            }
        }
        else if(item_type === 0x0001){
            //type_ids  从文件开头到类型标识符列表的偏移量；如果 type_ids_size == 0（不可否认是一种奇怪的极端情况），则该值为 0。该偏移量（如果为非零值）应该是到 type_ids 区段开头的偏移量。
            const header_string_id_size = dexptr.add(0x38).readUInt();
            const header_string_id_offset = dexptr.add(0x38 + 4).readUInt(); 


            if(header_string_id_size !== map_item_size){
                send(`[bad dex skip] map item header_string_id_size(${header_string_id_size}) !== map_item_size(${map_item_size}): idx:${i} `)
                return false;
            }

 
            if (header_string_id_offset !== map_item_offset) {
                send(`[bad dex skip] map item header_string_id_offset(${header_string_id_offset}) !== map_item_offset(${map_item_offset}): idx:${i} `)
                return false;
            }

        }
        else if(item_type === 0x0002){
            //type_ids  从文件开头到类型标识符列表的偏移量；如果 type_ids_size == 0（不可否认是一种奇怪的极端情况），则该值为 0。该偏移量（如果为非零值）应该是到 type_ids 区段开头的偏移量。
            const header_type_ids_size = dexptr.add(0x3C).readUInt();
            const header_type_ids_offset = dexptr.add(0x3C + 4).readUInt();
            
            //类型标识符列表中的元素数量，最多为 65535
            if(map_item_size > 65535){
                return false;
            }

            if (header_type_ids_size !== map_item_size) {
                send(`[bad dex skip] map item header_type_ids_size(${header_type_ids_size}) !== map_item_size(${map_item_size}): idx:${i} `)
                return false;
            }
            if (header_type_ids_offset !== map_item_offset) {
                send(`[bad dex skip] map item header_type_ids_offset(${header_type_ids_offset}) !== map_item_offset(${map_item_offset}): idx:${i} `)
                return false;
            }

        }
        else{
            // nop
            continue;
        
        }
    }


    // 已知的，怎么也的多于未知的吧。
    return mustOk  &&  processed_type.keys.length > unknown_type.keys.length;
}


function get_dex_real_size(dexptr: NativePointer, range_base: NativePointer, range_end: NativePointer): Number {
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

function get_maps_address(dexptr: NativePointer, range_base: NativePointer, range_end: NativePointer): NativePointer | null {
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

function get_maps_end(maps: NativePointer, range_base: NativePointer, range_end: NativePointer): NativePointer | null {
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


function verify(dexptr: NativePointer, range: RangeDetails, enable_verify_maps: boolean): boolean {

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
            return verify_by_maps(dexptr, maps_address,range.base, range_end)
        } else {

            // TODO: 读取头的大小，如果这里读出来的都是正确的，后面为啥还修复？ 
            return dexptr.add(0x3C).readUInt() === 0x70;
        }
    }

    return false;

}

function verify_ids_off(dexptr: NativePointer, dex_size: Number) {
    
    const string_ids_off = dexptr.add(0x3C).readUInt();
    const type_ids_off = dexptr.add(0x44).readUInt();
    const proto_ids_off = dexptr.add(0x4C).readUInt();
    const field_ids_off = dexptr.add(0x54).readUInt();
    const method_ids_off = dexptr.add(0x5C).readUInt();

    //考虑特殊情况，添加一下
    // xxx_size == 0（不可否认是一种奇怪的极端情况），则该值为 0

    return string_ids_off < dex_size && (string_ids_off >= 0x70 || string_ids_off === 0)
        && type_ids_off < dex_size && (type_ids_off >= 0x70|| type_ids_off === 0)
        && proto_ids_off < dex_size && (proto_ids_off >= 0x70|| proto_ids_off === 0)
        && field_ids_off < dex_size && (field_ids_off >= 0x70|| field_ids_off === 0)
        && method_ids_off < dex_size && (method_ids_off >= 0x70|| method_ids_off === 0);

}

export function searchDex(deepSearch: boolean) {
    const result: any = [];

    //Process.enumerateRanges('r--') 这是用于遍历当前进程中所有可以读的内存段，毕竟不能读的内存区域是不能被 VM 执行的 (Native 可以)。想必不难理解。
    Process.enumerateRanges('r--').forEach(function (range: RangeDetails) {
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
                    send(`found normal dex\\n begin header, addr:${match.address}, size:${dex_size}`)
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
                .concat(
                    Memory.scanSync(range.base, range.size, "70 00 00 00 12 34 56 78")
                ).forEach(function (match) {
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
                        send(`DeepSearch found 'not dex\\n begin' header. , addr:${range.base}, size:${real_dex_size}`)
                        if (max_size != real_dex_size) {
                            result.push({
                                "addr": dex_base,
                                "size": max_size
                            });
                        }
                    }
                })
            } else {
                
                if (range.base.readCString(4) != "dex\n" && verify(range.base, range, true)) {
                    const real_dex_size = get_dex_real_size(range.base, range.base, range.base.add(range.size));
                    send(`found 'not dex\\n begin' header. , addr:${range.base}, size:${real_dex_size}`)
                    result.push({
                        "addr": range.base,
                        "size": real_dex_size
                    });
                }
            }

        } catch (e) {
            console.log(e);
        }
    });

    return result;
}