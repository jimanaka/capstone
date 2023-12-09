import React from "react";

import { setFuncPaneWidth } from "../redux/slice/codeListingSlice";

import CodeView from "./CodeView";
import ResizeSpacer from "./ResizeSpacer";
import SplitPane from "./SplitPane";

const CodeListing = () => {
  return (
    <div className="p-8">
      <div className="flex flex-col justify-center space-y-3">
        <SplitPane
          direction="vertical"
          selector={(state) => state.codeListing.funcPaneWidth}
          leftWidthReducer={setFuncPaneWidth}
          leftId="left"
        >
          <CodeView id="left">function listing</CodeView>
          <ResizeSpacer />
          <CodeView>Disassembly</CodeView>
        </SplitPane>
        <ResizeSpacer />
        <CodeView>some other stuff maybe?</CodeView>
      </div>
    </div>
  );
};

export default CodeListing;
