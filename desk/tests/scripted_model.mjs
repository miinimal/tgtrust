/**
 * A fake LLM client that replays a fixed script of tool calls and answers.
 *
 * Pass it as ctx.llm to the runtime's runAgent. Each chat() call returns the next step
 * and records the tools and messages it was given, so a test can check them.
 */
export class ScriptedModel {
  /**
   * Create the model from its script.
   *
   * :param steps: A list of steps. A step is {tool, arguments} for a tool call or {text} for an answer.
   */
  constructor(steps) {
    this.steps = steps;
    this.calls = [];
  }

  /**
   * Return the next scripted reply in the shape the runtime expects.
   *
   * :param request: The runtime's request, with tools and messages.
   * :return: A reply with content and toolCalls.
   * :raises Error: When the runtime asks for more replies than the script has.
   */
  async chat(request) {
    // Copy the lists: the runner keeps appending to the same messages array.
    this.calls.push({
      tools: Array.from(request.tools || []),
      messages: Array.from(request.messages || []),
    });
    const step = this.steps[this.calls.length - 1];
    if (step === undefined) {
      throw new Error(`ScriptedModel ran out of steps after ${this.steps.length} replies.`);
    }
    if (step.tool) {
      return {
        content: "",
        toolCalls: [
          {
            id: `call-${this.calls.length}`,
            type: "function",
            function: {
              name: step.tool,
              arguments: JSON.stringify(step.arguments || {}),
            },
          },
        ],
      };
    }
    return {
      content: step.text,
      toolCalls: [],
    };
  }

  /**
   * Return the names of the tools offered on a given call.
   *
   * :param index: The zero-based call number.
   * :return: The tool names.
   */
  toolNames(index) {
    const names = [];
    for (const tool of this.calls[index].tools) {
      names.push(tool.function.name);
    }
    return names;
  }

  /**
   * Return the parsed tool results the runtime sent back on a given call.
   *
   * :param index: The zero-based call number.
   * :return: The parsed tool messages.
   */
  toolResults(index) {
    const results = [];
    for (const message of this.calls[index].messages) {
      if (message.role === "tool") {
        results.push(JSON.parse(message.content));
      }
    }
    return results;
  }
}
