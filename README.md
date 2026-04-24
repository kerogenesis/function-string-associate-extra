Function String Associate Extra for IDA 9+
---

You probably already know about a plugin called Function String Associate, which generates comments to functions based on the strings contained in those functions. For example:
```C++
// #STR: "param2", "NSystemMessageManager::AddSystemMessageParam", "param1"
int __stdcall sub_101EFF40(int a1, int a2)
{
...
case 4:
      FString::FString(v6, aParam1); // "param1"
      LOBYTE(v10) = 8;
      sub_101FD9F0(v20);
      LOBYTE(v10) = 2;
      FString::~FString(v6);
      FString::FString(v14, aParam2); // "param2"
      LOBYTE(v10) = 9;
      sub_101FD9F0(&a2);
      LOBYTE(v10) = 2;
      FString::~FString(v14);
      NConsoleWnd::GetMSName(v20[0], a2);
      goto LABEL_10;
...
}
```

### Why do we need another version?
As you can see, the plugin added a comment with the strings found in the functions.

You might also see `"NSystemMessageManager::AddSystemMessageParam"` in this comment. It's because, in some apps or games (like L2), most of the functions in the DLL have an error handler that contains the name of the function. My version also renames `sub_bla-bla-bla-blah` to the function name. This makes the research process a hundred times easier.

### Install
Just copy FunctionStringAssociateExtra.py to your IDA "plugins" folder `%APPDATA%/Hex-Rays/IDA Pro/plugins`

### How to run it 
Invoke it using Edit → Plugins → Function String Associate Extra in the IDA menu.

### Thx to
Sirmabus and oxiKKKK for the plugin base <3
