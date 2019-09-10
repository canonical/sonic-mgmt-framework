package transformer

import (
    "fmt"
    "strings"
    "reflect"
    "translib/db"
    "github.com/openconfig/goyang/pkg/yang"
    "github.com/openconfig/gnmi/proto/gnmi"
    "github.com/openconfig/ygot/ygot"
    log "github.com/golang/glog"
)

/* Create db key from datd xpath(request) */
func keyFromXpathCreate(keyList []string) string {
    keyOut := ""
    for i, k := range keyList {
        if i > 0 { keyOut += "_" }
        if strings.Contains(k, ":") {
            k = strings.Split(k, ":")[1]
        }
        keyOut += strings.Split(k, "=")[1]
    }
    return keyOut
}

/* Create db key from data xpath(request) */
func keyCreate(keyPrefix string, xpath string, data interface{}) string {
    yangEntry := xSpecMap[xpath].yangEntry
    if len(keyPrefix) > 0 { keyPrefix += "|" }

    keyVal := ""
    for i, k := range (strings.Split(yangEntry.Key, " ")) {
        if i > 0 { keyVal = keyVal + "_" }
        val := fmt.Sprint(data.(map[string]interface{})[k])
        if strings.Contains(val, ":") {
            val = strings.Split(val, ":")[1]
        }
        keyVal += val
    }
    keyPrefix += string(keyVal)
    return keyPrefix
}

/* Copy redis-db source to destn map */
func mapCopy(destnMap map[string]map[string]db.Value, srcMap map[string]map[string]db.Value) {
   for table, tableData := range srcMap {
        _, ok := destnMap[table]
        if !ok {
            destnMap[table] = make(map[string]db.Value)
        }
        for rule, ruleData := range tableData {
            _, ok = destnMap[table][rule]
            if !ok {
                 destnMap[table][rule] = db.Value{Field: make(map[string]string)}
            }
            for field, value := range ruleData.Field {
                destnMap[table][rule].Field[field] = value
            }
        }
   }
}

func parentXpathGet(xpath string) string {
    path := ""
    if len(xpath) > 0 {
		p := strings.Split(xpath, "/")
		path = strings.Join(p[:len(p)-1], "/")
	}
    return path
}

func isYangResType(ytype string) bool {
    if ytype == "choose" || ytype == "case" {
        return true
    }
    return false
}

func yangTypeGet(entry *yang.Entry) string {
    if entry != nil && entry.Node != nil {
        return entry.Node.Statement().Keyword
    }
    return ""
}

func dbKeyToYangDataConvert(uri string, xpath string, dbKey string) (map[string]string, string, string, error) {
    var kLvlValList []string
    keyDataList := strings.Split(dbKey, "|")
    keyNameList := yangKeyFromEntryGet(xSpecMap[xpath].yangEntry)
    id          := xSpecMap[xpath].keyLevel
    jsonData    := ""
    uriWithKey  := fmt.Sprintf("%v", xpath)

    /* if uri contins key, use it else use xpath */
    if strings.Contains(uri, "[") {
        uriWithKey  = fmt.Sprintf("%v", uri)
    }

    if len(xSpecMap[xpath].xfmrKey) > 0 {
        var d *db.DB
        ret, err := XlateFuncCall(dbToYangXfmrFunc(xSpecMap[xpath].xfmrKey), d, GET, dbKey)
        if err != nil {
            return nil, "","",err
        }
        rmap  := ret[0].Interface().(map[string]string)
        for k, v := range rmap {
            jsonData += fmt.Sprintf("\"%v\" : \"%v\",\r\n", k, v)
            uriWithKey += fmt.Sprintf("[%v=%v]", k, v)
        }
        return rmap, uriWithKey, jsonData, nil
    }
    kLvlValList = append(kLvlValList, keyDataList[id])

    if len(keyNameList) > 1 {
        kLvlValList = strings.Split(keyDataList[id], "_")
    }

    /* TODO: Need to add leaf-ref related code in here and remove this code*/
    kvalExceedFlag := false
    chgId := -1
    if len(keyNameList) < len(kLvlValList) {
        kvalExceedFlag = true
        chgId = len(keyNameList) - 1
    }

    rmap := make(map[string]string)
    for i, kname := range keyNameList {
        kval := kLvlValList[i]

        /* TODO: Need to add leaf-ref related code in here and remove this code*/
        if kvalExceedFlag && (i == chgId) {
            kval = strings.Join(kLvlValList[chgId:], "_")
        }

        jsonData   += fmt.Sprintf("\"%v\" : \"%v\",", kname, kval)
        uriWithKey += fmt.Sprintf("[%v=%v]", kname, kval)
        rmap[kname] = kval
    }

    return rmap, uriWithKey, jsonData, nil
 }


func contains(sl []string, str string) bool {
    for _, v := range sl {
        if v == str {
            return true
        }
    }
    return false
}


func isSubtreeRequest(targetUriPath string, nodePath string) bool {
    return strings.HasPrefix(targetUriPath, nodePath)
}

func getYangPathFromUri(uri string) (string, error) {
    var path *gnmi.Path
    var err error

    path, err = ygot.StringToPath(uri, ygot.StructuredPath, ygot.StringSlicePath)
    if err != nil {
        log.Errorf("Error in uri to path conversion: %v", err)
        return "", err
    }

    yangPath, yperr := ygot.PathToSchemaPath(path)
    if yperr != nil {
        log.Errorf("Error in Gnmi path to Yang path conversion: %v", yperr)
        return "", yperr
    }

    return yangPath, err
}

func yangKeyFromEntryGet(entry *yang.Entry) []string {
    var keyList []string
    for _, key := range strings.Split(entry.Key, " ") {
        keyList = append(keyList, key)
    }
    return keyList
}

func isCvlYang(path string) bool {
    if strings.HasPrefix(path, "/sonic") {
        return true
    }
    return false
}

func keyJsonDataAdd(keyNameList []string, keyStr string, jsonData string) string {
    keyValList := strings.Split(keyStr, "|")
    if len(keyNameList) != len(keyValList) {
        return ""
    }

    for i, keyName := range keyNameList {
        jsonData += fmt.Sprintf("\"%v\" : \"%v\",", keyName, keyValList[i])
    }
    jsonData = strings.TrimRight(jsonData, ",")
    return jsonData
}

func yangToDbXfmrFunc(funcName string) string {
    return ("YangToDb_" + funcName)
}

func uriWithKeyCreate (uri string, xpathTmplt string, data interface{}) string {
    yangEntry := xSpecMap[xpathTmplt].yangEntry
    for _, k := range (strings.Split(yangEntry.Key, " ")) {
        uri += fmt.Sprintf("[%v=%v]", k, data.(map[string]interface{})[k])
    }
    return uri
}

func xpathRootNameGet(path string) string {
    pathl := strings.Split(path, "/")
    return ("/" + pathl[1])
}

func getDbNum(xpath string ) db.DBNum {
    _, ok := xSpecMap[xpath]
    if ok {
        xpathInfo := xSpecMap[xpath]
        return xpathInfo.dbIndex
    }
    // Default is ConfigDB
    return db.ConfigDB
}

func dbToYangXfmrFunc(funcName string) string {
    return ("DbToYang_" + funcName)
}

func uriModuleNameGet(uri string) (string, error) {
	var err error
	result := ""
	if len(uri) == 0 {
		log.Error("Empty uri string supplied")
		return result, err
	}
	urislice := strings.Split(uri, ":")
	if len(urislice) == 1 {
		log.Errorf("uri string %s does not have module name", uri)
		return result, err
	}
	moduleNm := strings.Split(urislice[0], "/")
	result = moduleNm[1]
	if len(strings.Trim(result, " ")) == 0 {
		log.Error("Empty module name")
		err = fmt.Errorf("No module name found in uri %s", uri)
        }
	log.Info("module name = ", result)
	return result, err
}

func recMap(rMap interface{}, name []string, id int, max int) {
    if id == max {
        return
    }
    val := name[id]
       if reflect.ValueOf(rMap).Kind() == reflect.Map {
               data := reflect.ValueOf(rMap)
               dMap := data.Interface().(map[string]interface{})
               _, ok := dMap[val]
               if ok {
                       recMap(dMap[val], name, id+1, max)
               } else {
                       dMap[val] = make(map[string]interface{})
                       recMap(dMap[val], name, id+1, max)
               }
       }
       return
}

func mapCreate(xpath string) map[string]interface{} {
    retMap   := make(map[string]interface{})
    attrList := strings.Split(xpath, "/")
    alLen    := len(attrList)
    recMap(retMap, attrList, 1, alLen)
    return retMap
}

func mapInstGet(name []string, id int, max int, inMap interface{}) map[string]interface{} {
    result := reflect.ValueOf(inMap).Interface().(map[string]interface{})
    if id == max {
        return result
    }
    val := name[id]
    if reflect.ValueOf(inMap).Kind() == reflect.Map {
        data := reflect.ValueOf(inMap)
        dMap := data.Interface().(map[string]interface{})
        _, ok := dMap[val]
        if ok {
            result = mapInstGet(name, id+1, max, dMap[val])
        } else {
            return result
        }
    }
    return result
}

func mapGet(xpath string, inMap map[string]interface{}) map[string]interface{} {
    attrList := strings.Split(xpath, "/")
    alLen    := len(attrList)
    recMap(inMap, attrList, 1, alLen)
    retMap := mapInstGet(attrList, 1, alLen, inMap)
    return retMap
}