// import { TextEncoder } from "util";

function so_test1(){
    let modules = Process.enumerateModules();
    for (const m of modules) {
        let exports = m.enumerateExports();
        for (const exp of exports) {
            //console.log(JSON.stringify(exp));
            if(exp.name.indexOf('onCreate') != -1){
                console.log('so  onCreate found :', JSON.stringify(exp));
            }
        }
    }
}

function testHook1(){
    let loadedCls = Java.enumerateLoadedClasses({
        onMatch:function(name,handle){
            if(name.indexOf('com.yssenlin') != -1){
                console.log(name, handle);
            }
        },
        onComplete:function(){
            console.log('------- all class found! ----------');
        }
    });
    
      
    let mainActivity = Java.use('com.yssenlin.app.MainActivity');
    let methods = mainActivity.class.getDeclaredMethods();
    for (const iterator of methods) {
        console.log(iterator)
    }
    //console.log(JSON.stringify(mainActivity.$ownMembers,null,4));

    //send(mainActivity.onCreate)
}

function hookTest2(){
    
    let shufferMap = Java.use("com.xiaojianbang.app.ShufferMap");
    shufferMap.show.implementation = function(m:any){
        console.log(m);
        for(let k of m.keySet().toArray()){
            console.log(k, '=', m.get(k));
        }
        // // console.log(m, m.get("user"), JSON.stringify(m.class.getDeclaredMethods().map(d=>d.toString()),null,4));
        // console.log("--------------------------" + new Date() + "--------------------------");
        // console.log(JSON.stringify(m.keySet().class.getDeclaredMethods().map(d=>d.toString()),null,4));
        m.put("user","user_string");
        console.log(m);
        return this.show(m);
    }
  
}

function hookTest3(){
    let rsa = Java.use("com.xiaojianbang.app.RSA");
    let data  = "hello world";
    
    let dataBytes = new TextEncoder().encode(data);
    console.log(dataBytes)

    let encDataBytes = rsa.encrypt(dataBytes );
    console.log(encDataBytes)
}



function main(){
    console.log("--------------------------" + new Date() + "--------------------------");
    Java.perform(()=>{
       // testHook1();
       hookTest2();
       hookTest3();
    })
}


setImmediate(main);
