package callgraph

import (
	"reflect"
	"testing"
)

// A call on a field or parameter binds through the type it is declared with.
func TestSourceReceiverTypes(t *testing.T) {
	javaController := "package a.web;\n\npublic class DirectoryController {\n    private final StaffService directory;\n\n" +
		"    public DirectoryController(StaffService directory) {\n        this.directory = directory;\n    }\n\n" +
		"    public List<String> search(String q) {\n        return directory.find(q);\n    }\n}\n"
	javaService := "package a.service;\n\npublic class StaffService {\n    public List<String> find(String q) {\n        return ldap.search(q);\n    }\n}\n"

	tests := []struct {
		name  string
		files map[string]string
		file  string
		want  map[string]Callee
	}{
		{
			name:  "java: a constructor-injected field",
			files: map[string]string{"web/DirectoryController.java": javaController, "service/StaffService.java": javaService},
			file:  "web/DirectoryController.java",
			want:  map[string]Callee{"directory.find": {File: "service/StaffService.java", Func: "find"}},
		},
		{
			name: "java: an interface field binds to its one implementation",
			files: map[string]string{
				"web/DirectoryController.java":  javaController,
				"service/StaffService.java":     "package a.service;\n\npublic interface StaffService {\n    List<String> find(String q);\n}\n",
				"service/StaffServiceImpl.java": "package a.service;\n\npublic class StaffServiceImpl implements StaffService {\n    public List<String> find(String q) {\n        return ldap.search(q);\n    }\n}\n",
			},
			file: "web/DirectoryController.java",
			want: map[string]Callee{"directory.find": {File: "service/StaffServiceImpl.java", Func: "find"}},
		},
		{
			name: "java: two implementations bind to neither",
			files: map[string]string{
				"web/DirectoryController.java": javaController,
				"service/StaffService.java":    "package a.service;\n\npublic interface StaffService {\n    List<String> find(String q);\n}\n",
				"service/LdapStaff.java":       "package a.service;\n\npublic class LdapStaff implements StaffService {\n    public List<String> find(String q) {\n        return ldap.search(q);\n    }\n}\n",
				"service/DbStaff.java":         "package a.service;\n\npublic class DbStaff implements StaffService {\n    public List<String> find(String q) {\n        return db.query(q);\n    }\n}\n",
			},
			file: "web/DirectoryController.java",
			want: nil,
		},
		{
			name: "java: a name declared with two types binds to neither",
			files: map[string]string{
				"web/DirectoryController.java": "package a.web;\n\npublic class DirectoryController {\n    void a(StaffService directory) {\n        directory.find(1);\n    }\n\n" +
					"    void b(OtherService directory) {\n        directory.find(2);\n    }\n}\n",
				"service/StaffService.java": javaService,
				"service/OtherService.java": "package a.service;\n\npublic class OtherService {\n    public void find(int q) {\n        run(q);\n    }\n}\n",
			},
			file: "web/DirectoryController.java",
			want: nil,
		},
		{
			name: "java: a declaration inside a comment is not read",
			files: map[string]string{
				"web/DirectoryController.java": "package a.web;\n\npublic class DirectoryController {\n    // private StaffService directory;\n\n" +
					"    public List<String> search(String q) {\n        return directory.find(q);\n    }\n}\n",
				"service/StaffService.java": javaService,
			},
			file: "web/DirectoryController.java",
			want: nil,
		},
		{
			name: "typescript: a constructor parameter property",
			files: map[string]string{
				"src/a/a.controller.ts": "export class AController {\n  constructor(private readonly attachments: AttachmentsService) {}\n\n" +
					"  fetchIt(url: string) {\n    return this.attachments.capture(url);\n  }\n}\n",
				"src/a/a.service.ts": "export class AttachmentsService {\n  async capture(url: string) {\n    return fetch(url);\n  }\n}\n",
			},
			file: "src/a/a.controller.ts",
			want: map[string]Callee{"this.attachments.capture": {File: "src/a/a.service.ts", Func: "capture"}},
		},
		{
			name: "python: an attribute assigned a constructed instance",
			files: map[string]string{
				"app/views.py": "from app.repo import UserRepository\n\n\nclass View:\n    def __init__(self):\n        self.users = UserRepository()\n\n" +
					"    def get(self, name):\n        return self.users.by_name(name)\n",
				"app/repo.py": "class UserRepository:\n    def by_name(self, name):\n        return db.execute(\"SELECT * FROM u WHERE n = '\" + name + \"'\")\n",
			},
			file: "app/views.py",
			want: map[string]Callee{"self.users.by_name": {File: "app/repo.py", Func: "by_name"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := buildSource(t, tc.files, nil)
			got := map[string]Callee{}
			for call, c := range g.CrossFileCallees(tc.file) {
				if _, keep := tc.want[call]; keep || call == "directory.find" || call == "this.attachments.capture" || call == "self.users.by_name" {
					got[call] = c
				}
			}
			if len(got) == 0 {
				got = nil
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("callees of %s = %v, want %v", tc.file, got, tc.want)
			}
		})
	}
}

func TestReceiverField(t *testing.T) {
	for qual, want := range map[string]string{
		"svc": "svc", "this.svc": "svc", "self.svc": "svc", "a.b": "", "this.a.b": "", "f()": "", "": "",
	} {
		if got := receiverField(qual); got != want {
			t.Errorf("receiverField(%q) = %q, want %q", qual, got, want)
		}
	}
}
