#include <gtest/gtest.h>
#include "../adapters/gdbmiconnector.h"

// Remove Binary Ninja dependencies for standalone test
namespace BinaryNinja {
    static void LogDebug(const char* format, ...) {
        // Mock implementation - do nothing for tests
    }
    static void LogInfo(const char* format, ...) {
        // Mock implementation - do nothing for tests
    }
    static void LogWarn(const char* format, ...) {
        // Mock implementation - do nothing for tests
    }
    static void LogError(const char* format, ...) {
        // Mock implementation - do nothing for tests
    }
}

class MiParserTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize Binary Ninja core if needed
    }

    void TearDown() override {
        // Clean up if needed
    }
};

// Test basic string parsing
TEST_F(MiParserTest, BasicString) {
    MiValue result = MiValue::Parse("\"hello world\"");
    EXPECT_TRUE(result.IsString());
    EXPECT_EQ(result.GetString(), "hello world");
}

// Test basic dictionary parsing
TEST_F(MiParserTest, BasicDictionary) {
    MiValue result = MiValue::Parse("id=\"i1\",pid=\"42000\"");
    EXPECT_TRUE(result.IsDict());
    EXPECT_EQ(result["id"].GetString(), "i1");
    EXPECT_EQ(result["pid"].GetString(), "42000");
}

// Test array parsing
TEST_F(MiParserTest, BasicArray) {
    MiValue result = MiValue::Parse("result=[\"one\",\"two\",\"three\"]");
    EXPECT_TRUE(result["result"].IsList());
    EXPECT_EQ(result["result"].size(), 3);
    EXPECT_EQ(result["result"][0].GetString(), "one");
    EXPECT_EQ(result["result"][1].GetString(), "two");
    EXPECT_EQ(result["result"][2].GetString(), "three");
}

// Test nested dictionary
TEST_F(MiParserTest, NestedDictionary) {
    MiValue result = MiValue::Parse("frame={addr=\"0x08072c52\",func=\"OS_TaskIdle\",args=[{name=\"p_arg\",value=\"<optimized out>\"}],arch=\"armv3m\"},thread-id=\"1\",stopped-threads=\"all\"");
    EXPECT_TRUE(result.IsDict());
    EXPECT_TRUE(result["frame"].IsDict());
    EXPECT_EQ(result["frame"]["addr"].GetString(), "0x08072c52");
    EXPECT_EQ(result["frame"]["func"].GetString(), "OS_TaskIdle");
	EXPECT_EQ(result["frame"]["args"][0]["name"].GetString(), "p_arg");
	EXPECT_EQ(result["frame"]["args"][0]["value"].GetString(), "<optimized out>");
}

// Test the specific problematic case that was causing infinite loops
TEST_F(MiParserTest, VarListChildrenWithChildPattern) {
    std::string input = "numchild=\"2\",children=[child={name=\"var2.0\",exp=\"0\",numchild=\"31\",value=\"{...}\",type=\"struct custom_cmplx_t\"},child={name=\"var2.1\",exp=\"1\",numchild=\"31\",value=\"{...}\",type=\"struct custom_cmplx_t\"}],has_more=\"0\"";
    
    MiValue result = MiValue::Parse(input);
    EXPECT_TRUE(result.IsDict());
    
    // Check top-level fields
    EXPECT_EQ(result["numchild"].GetString(), "2");
    EXPECT_EQ(result["has_more"].GetString(), "0");
    
    // Check children array
    EXPECT_TRUE(result["children"].IsList());
    EXPECT_EQ(result["children"].size(), 2);
    
    // Check first child
    MiValue child0 = result["children"][0];
    EXPECT_TRUE(child0.IsDict());
    EXPECT_TRUE(child0["child"].IsDict());
    EXPECT_EQ(child0["child"]["name"].GetString(), "var2.0");
    EXPECT_EQ(child0["child"]["exp"].GetString(), "0");
    EXPECT_EQ(child0["child"]["numchild"].GetString(), "31");
    EXPECT_EQ(child0["child"]["value"].GetString(), "{...}");
    EXPECT_EQ(child0["child"]["type"].GetString(), "struct custom_cmplx_t");
    
    // Check second child
    MiValue child1 = result["children"][1];
    EXPECT_TRUE(child1.IsDict());
    EXPECT_TRUE(child1["child"].IsDict());
    EXPECT_EQ(child1["child"]["name"].GetString(), "var2.1");
    EXPECT_EQ(child1["child"]["exp"].GetString(), "1");
    EXPECT_EQ(child1["child"]["numchild"].GetString(), "31");
    EXPECT_EQ(child1["child"]["value"].GetString(), "{...}");
    EXPECT_EQ(child1["child"]["type"].GetString(), "struct custom_cmplx_t");
}

// Test thread information response
TEST_F(MiParserTest, ThreadInfoResponse) {
    std::string input = "threads=[{id=\"1\",target-id=\"Remote target\",frame={level=\"0\",addr=\"0x08072c52\",func=\"OS_TaskIdle\",args=[{name=\"p_arg\",value=\"<optimized out>\"}],arch=\"armv3m\"},state=\"stopped\"}],current-thread-id=\"1\"";
    
    MiValue result = MiValue::Parse(input);
    EXPECT_TRUE(result.IsDict());
    
    EXPECT_TRUE(result["threads"].IsList());
    EXPECT_EQ(result["threads"].size(), 1);
    
    MiValue thread = result["threads"][0];
    EXPECT_TRUE(thread.IsDict());
    EXPECT_EQ(thread["id"].GetString(), "1");
    EXPECT_EQ(thread["target-id"].GetString(), "Remote target");
    EXPECT_EQ(thread["state"].GetString(), "stopped");
    
    EXPECT_TRUE(thread["frame"].IsDict());
    EXPECT_EQ(thread["frame"]["level"].GetString(), "0");
    EXPECT_EQ(thread["frame"]["addr"].GetString(), "0x08072c52");
    EXPECT_EQ(thread["frame"]["func"].GetString(), "OS_TaskIdle");
    EXPECT_EQ(thread["frame"]["arch"].GetString(), "armv3m");
    
    EXPECT_TRUE(thread["frame"]["args"].IsList());
    EXPECT_EQ(thread["frame"]["args"].size(), 1);
    EXPECT_EQ(thread["frame"]["args"][0]["name"].GetString(), "p_arg");
    EXPECT_EQ(thread["frame"]["args"][0]["value"].GetString(), "<optimized out>");
}

// Test register values response
TEST_F(MiParserTest, RegisterValuesResponse) {
    std::string input = "register-values=[{number=\"0\",value=\"0x07070707\"},{number=\"1\",value=\"0x2001eea8\"},{number=\"2\",value=\"0x02020202\"}]";
    
    MiValue result = MiValue::Parse(input);
    EXPECT_TRUE(result.IsDict());
    
    EXPECT_TRUE(result["register-values"].IsList());
    EXPECT_EQ(result["register-values"].size(), 3);
    
    EXPECT_EQ(result["register-values"][0]["number"].GetString(), "0");
    EXPECT_EQ(result["register-values"][0]["value"].GetString(), "0x07070707");
    
    EXPECT_EQ(result["register-values"][1]["number"].GetString(), "1");
    EXPECT_EQ(result["register-values"][1]["value"].GetString(), "0x2001eea8");
    
    EXPECT_EQ(result["register-values"][2]["number"].GetString(), "2");
    EXPECT_EQ(result["register-values"][2]["value"].GetString(), "0x02020202");
}

// Test breakpoint information
TEST_F(MiParserTest, BreakpointInfo) {
    std::string input = "bkpt={number=\"1\",type=\"hw breakpoint\",disp=\"keep\",enabled=\"y\",addr=\"0x080fc186\",at=\"<sub_func+6>\",thread-groups=[\"i1\"],times=\"0\",original-location=\"*0x80fc186\"}";
    
    MiValue result = MiValue::Parse(input);
    EXPECT_TRUE(result.IsDict());
    
    EXPECT_TRUE(result["bkpt"].IsDict());
    EXPECT_EQ(result["bkpt"]["number"].GetString(), "1");
    EXPECT_EQ(result["bkpt"]["type"].GetString(), "hw breakpoint");
    EXPECT_EQ(result["bkpt"]["disp"].GetString(), "keep");
    EXPECT_EQ(result["bkpt"]["enabled"].GetString(), "y");
    EXPECT_EQ(result["bkpt"]["addr"].GetString(), "0x080fc186");
    EXPECT_EQ(result["bkpt"]["at"].GetString(), "<sub_func+6>");
    EXPECT_EQ(result["bkpt"]["times"].GetString(), "0");
    EXPECT_EQ(result["bkpt"]["original-location"].GetString(), "*0x80fc186");
    
    EXPECT_TRUE(result["bkpt"]["thread-groups"].IsList());
    EXPECT_EQ(result["bkpt"]["thread-groups"].size(), 1);
    EXPECT_EQ(result["bkpt"]["thread-groups"][0].GetString(), "i1");
}

// Test memory response
TEST_F(MiParserTest, MemoryResponse) {
    std::string input = "memory=[{begin=\"0x2001ee00\",offset=\"0x00000000\",end=\"0x2001ef00\",contents=\"c584070016480b0000000000\"}]";
    
    MiValue result = MiValue::Parse(input);
    EXPECT_TRUE(result.IsDict());
    
    EXPECT_TRUE(result["memory"].IsList());
    EXPECT_EQ(result["memory"].size(), 1);
    
    MiValue memory = result["memory"][0];
    EXPECT_TRUE(memory.IsDict());
    EXPECT_EQ(memory["begin"].GetString(), "0x2001ee00");
    EXPECT_EQ(memory["offset"].GetString(), "0x00000000");
    EXPECT_EQ(memory["end"].GetString(), "0x2001ef00");
    EXPECT_EQ(memory["contents"].GetString(), "c584070016480b0000000000");
}

// Test stack frames
TEST_F(MiParserTest, StackFrames) {
    std::string input = "stack=[frame={level=\"0\",addr=\"0x08072c52\",func=\"OS_TaskIdle\",arch=\"armv3m\"},frame={level=\"1\",addr=\"0xfffffffe\",func=\"<signal handler called>\"}]";
    
    MiValue result = MiValue::Parse(input);
    EXPECT_TRUE(result.IsDict());
    
    EXPECT_TRUE(result["stack"].IsList());
    EXPECT_EQ(result["stack"].size(), 2);
    
    EXPECT_EQ(result["stack"][0]["frame"]["level"].GetString(), "0");
    EXPECT_EQ(result["stack"][0]["frame"]["addr"].GetString(), "0x08072c52");
    EXPECT_EQ(result["stack"][0]["frame"]["func"].GetString(), "OS_TaskIdle");
    EXPECT_EQ(result["stack"][0]["frame"]["arch"].GetString(), "armv3m");
    
    EXPECT_EQ(result["stack"][1]["frame"]["level"].GetString(), "1");
    EXPECT_EQ(result["stack"][1]["frame"]["addr"].GetString(), "0xfffffffe");
    EXPECT_EQ(result["stack"][1]["frame"]["func"].GetString(), "<signal handler called>");
}

// Test empty array
TEST_F(MiParserTest, EmptyArray) {
    MiValue result = MiValue::Parse("empty_array=[]");
    EXPECT_TRUE(result.IsDict());
    EXPECT_TRUE(result["empty_array"].IsList());
    EXPECT_EQ(result["empty_array"].size(), 0);
}

// Test empty dictionary
TEST_F(MiParserTest, EmptyDictionary) {
    MiValue result = MiValue::Parse("empty_dict={}");
    EXPECT_TRUE(result.IsDict());
    EXPECT_TRUE(result["empty_dict"].IsDict());
    EXPECT_EQ(result["empty_dict"].size(), 0);
}

// Test complex nested structure
TEST_F(MiParserTest, ComplexNestedStructure) {
    std::string input = "response={result=\"done\",data={items=[{id=1,values=[1,2,3]},{id=2,values=[4,5,6]}],count=2}}";
    
    MiValue result = MiValue::Parse(input);
    EXPECT_TRUE(result.IsDict());
    EXPECT_TRUE(result["response"].IsDict());
    EXPECT_EQ(result["response"]["result"].GetString(), "done");
    
    EXPECT_TRUE(result["response"]["data"].IsDict());
    EXPECT_EQ(result["response"]["data"]["count"].GetString(), "2");
    
    EXPECT_TRUE(result["response"]["data"]["items"].IsList());
    EXPECT_EQ(result["response"]["data"]["items"].size(), 2);
    
    EXPECT_EQ(result["response"]["data"]["items"][0]["id"].GetString(), "1");
    EXPECT_TRUE(result["response"]["data"]["items"][0]["values"].IsList());
    EXPECT_EQ(result["response"]["data"]["items"][0]["values"].size(), 3);
}

// Test that no infinite loops occur with malformed input
TEST_F(MiParserTest, MalformedInputNoInfiniteLoop) {
    // This should not cause an infinite loop
    std::string input = "malformed=[unclosed array";
    EXPECT_NO_THROW({
        MiValue result = MiValue::Parse(input);
        // We don't care about the result, just that it doesn't hang
    });
    
    // Test with unclosed string
    input = "key=\"unclosed string";
    EXPECT_NO_THROW({
        MiValue result = MiValue::Parse(input);
    });
    
    // Test with random garbage
    input = "asdf1234!@#$%^&*()";
    EXPECT_NO_THROW({
        MiValue result = MiValue::Parse(input);
    });
}

// Test escaped characters in strings
TEST_F(MiParserTest, EscapedCharacters) {
    MiValue result = MiValue::Parse("key=\"value with \\\"quotes\\\" and \\\\ backslash\"");
    EXPECT_TRUE(result.IsDict());
    EXPECT_EQ(result["key"].GetString(), "value with \"quotes\" and \\ backslash");
}

// Test mixed array types (should handle gracefully)
TEST_F(MiParserTest, MixedArrayTypes) {
    std::string input = "mixed=[\"string\",123,true,{nested=\"value\"}]";
    MiValue result = MiValue::Parse(input);
    EXPECT_TRUE(result.IsDict());
    EXPECT_TRUE(result["mixed"].IsList());
    EXPECT_EQ(result["mixed"].size(), 4);
    
    // Should all be treated as strings in the current implementation
    EXPECT_EQ(result["mixed"][0].GetString(), "string");
    EXPECT_EQ(result["mixed"][1].GetString(), "123");
    EXPECT_EQ(result["mixed"][2].GetString(), "true");
    EXPECT_TRUE(result["mixed"][3].IsDict());
    EXPECT_EQ(result["mixed"][3]["nested"].GetString(), "value");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
