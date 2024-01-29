using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.CommandLine;
using System.CommandLine.DragonFruit;

using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace ob
{
    class ob
    {
        private static Random random = new Random();
        private static List<String> names = new List<string>();
        // Reference: https://stackoverflow.com/a/1344242/11567632
        public static string RandomString(int length)
        {
            const string chars = "7cec85d7bea779YV085N3MEL8eY789";
            string name = "";
            do {
                name = new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
            } while (names.Contains(name));

            return name;
        }

        public static void cleanAsm(ModuleDef md)
        {
            foreach (var type in md.GetTypes())
            {
                foreach (MethodDef method in type.Methods)
                {
                    // empty method check
                    if (!method.HasBody) continue;

                    method.Body.SimplifyBranches();
                    method.Body.OptimizeBranches(); 
                    //method.Body.OptimizeMacros();
                }
            }
        }

        // reference: https://github.com/CodeOfDark/Tutorials-StringEncryption
        public static void obfuscateStrings(ModuleDef md)
        {
            //foreach (var type in md.Types) // only gets parent(non-nested) classes

            // types(namespace.class) in module
            foreach (var type in md.GetTypes())
            {
                // methods in type
                foreach(MethodDef method in type.Methods)
                {
                    // empty method check
                    if (!method.HasBody) continue;
                    // iterate over instructions of method
                    for(int i = 0; i < method.Body.Instructions.Count(); i++)
                    {
                        // check for LoadString opcode
                        // CIL is Stackbased (data is pushed on stack rather than register)
                        // ref: https://en.wikipedia.org/wiki/Common_Intermediate_Language
                        // ld = load (push onto stack), st = store (store into variable)
                        if(method.Body.Instructions[i].OpCode == OpCodes.Ldstr)
                        {
                            // c# variable has for loop scope only
                            String regString = method.Body.Instructions[i].Operand.ToString();
                            String encString = Convert.ToBase64String(UTF8Encoding.UTF8.GetBytes(regString));
                            Console.WriteLine($"{regString} -> {encString}");
                            // methodology for adding code: write it in plain c#, compile, then view IL in dnspy
                            method.Body.Instructions[i].OpCode = OpCodes.Nop; // errors occur if instruction not replaced with Nop
                            method.Body.Instructions.Insert(i + 1,new Instruction(OpCodes.Call, md.Import(typeof(System.Text.Encoding).GetMethod("get_UTF8", new Type[] { })))); // Load string onto stack
                            method.Body.Instructions.Insert(i + 2, new Instruction(OpCodes.Ldstr, encString)); // Load string onto stack
                            method.Body.Instructions.Insert(i + 3, new Instruction(OpCodes.Call, md.Import(typeof(System.Convert).GetMethod("FromBase64String", new Type[] { typeof(string) })))); // call method FromBase64String with string parameter loaded from stack, returned value will be loaded onto stack
                            method.Body.Instructions.Insert(i + 4, new Instruction(OpCodes.Callvirt, md.Import(typeof(System.Text.Encoding).GetMethod("GetString", new Type[] { typeof(byte[]) })))); // call method GetString with bytes parameter loaded from stack 
                            i += 4; //skip the Instructions as to not recurse on them
                        }
                    }
                    //method.Body.KeepOldMaxStack = true;
                }
            }

        }

        public static void obfuscateClasses(ModuleDef md)
        {
            foreach (var type in md.GetTypes())
            {
                string encName = RandomString(20);
                Console.WriteLine($"{type.Name} -> {encName}");
                type.Name = encName;
            }

        }

        public static void obfuscateNamespace(ModuleDef md)
        {
            foreach (var type in md.GetTypes())
            {
                string encName = RandomString(20);
                Console.WriteLine($"{type.Namespace} -> {encName}");
                type.Namespace = encName;
            }

        }
        public static void obfuscateAssemblyInfo(ModuleDef md)
        {
            // obfuscate assembly name
            string encName = RandomString(20);
            Console.WriteLine($"{md.Assembly.Name} -> {encName}");
            md.Assembly.Name = encName;

            // obfuscate Assembly Attributes(AssemblyInfo) .rc file
            string[] attri = { "GuidAttribute", "AssemblyDescriptionAttribute", "AssemblyTitleAttribute", "AssemblyProductAttribute", "AssemblyCopyrightAttribute", "AssemblyCompanyAttribute","AssemblyFileVersionAttribute"};
            // "GuidAttribute", and assembly version can also be changed
            foreach (CustomAttribute attribute in md.Assembly.CustomAttributes) {
                if (attri.Any(attribute.AttributeType.Name.Contains)) {
                    string encAttri = RandomString(20);
                    Console.WriteLine($"{attribute.AttributeType.Name} = {encAttri}");
                    attribute.ConstructorArguments[0] = new CAArgument(md.CorLibTypes.String, new UTF8String(encAttri));
                }
            }
        }
        static void Main()
        {
            ModuleDef md = ModuleDefMD.Load(@"C:\\Users\\jsamm\\Desktop\\maldev\\CERT\\04 - Run Me\\InternalMonologue.exe");
            md.Name = RandomString(20);
            //obfuscateStrings(md);
            //obfuscateMethods(md);
            obfuscateClasses(md);
            obfuscateNamespace(md);
            obfuscateAssemblyInfo(md);

            cleanAsm(md);
            md.Write(@"C:\\Users\\jsamm\\Desktop\\maldev\\CERT\\04 - Run Me\\XXxnternal.exe");


        }
    }
}
