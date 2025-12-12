' 微信多开启动脚本
' 使用方法：双击此脚本即可启动微信并自动解除多开限制

Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

' 获取脚本所在目录
scriptPath = fso.GetParentFolderName(WScript.ScriptFullName)
toolPath = scriptPath & "\target\release\wechatmult.exe"

' 微信路径（请根据实际安装位置修改）
wechatPath = ""

' 如果默认路径不存在，尝试其他常见路径
If Not fso.FileExists(wechatPath) Then
    wechatPath = "C:\Program Files (x86)\Tencent\WeChat\WeChat.exe"
End If
If Not fso.FileExists(wechatPath) Then
    wechatPath = "D:\Program Files\Tencent\WeChat\WeChat.exe"
End If
If Not fso.FileExists(wechatPath) Then
    wechatPath = "D:\Program Files (x86)\Tencent\WeChat\WeChat.exe"
End If

' 检查微信是否存在
If Not fso.FileExists(wechatPath) Then
    MsgBox "未找到微信，请修改脚本中的 wechatPath 变量", vbCritical, "错误"
    WScript.Quit
End If

' 检查工具是否存在
If Not fso.FileExists(toolPath) Then
    MsgBox "未找到 wechatmult.exe，请先编译项目", vbCritical, "错误"
    WScript.Quit
End If

' 启动微信
WshShell.Run """" & wechatPath & """", 1, False

' 等待微信启动（2秒）
WScript.Sleep 2000

' 执行删除互斥锁（静默运行，以管理员权限）
WshShell.Run """" & toolPath & """ --kill-mutex-all", 0, True
