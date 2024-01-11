import React from "react";

import {
  setFuncPaneWidth,
  setDisassPaneWidth,
} from "../redux/slice/CodeListingSlice";

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
          leftId="funcPane"
        >
          <CodeView id="funcPane">function listing</CodeView>
          <ResizeSpacer />
          <div>
            <SplitPane
              direction="vertical"
              selector={(state) => state.codeListing.disassPaneWidth}
              leftWidthReducer={setDisassPaneWidth}
              leftId="disassPane"
            >
              <CodeView id="disassPane">disassembly Listing</CodeView>
              <ResizeSpacer />
              <CodeView>Decompilation Listing</CodeView>
            </SplitPane>
          </div>
        </SplitPane>
        <ResizeSpacer />
        <CodeView>some other stuff maybe?</CodeView>
      </div>
    </div>
  );
};

export default CodeListing;
