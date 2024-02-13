
      <ransition appear show={breakpointDialogIsOpen} as={Fragment}>
        <Dialog as="div" className="relative z-10" onClose={() => dispatch(setBreakpointDialogIsOpen(false))}>
          <Transition.Child
            as={Fragment}
            enter="ease-out duration-300"
            enterFrom="opacity-0"
            enterTo="opacity-100"
            leave="ease-in duration-200"
            leaveFrom="opacity-100"
            leaveTo="opacity-0"
          >
            <div className="fixed inset-0 bg-black/60" />
          </Transition.Child>

          <div className="fixed inset-0 overflow-y-auto">
            <div className="flex min-h-full items-center justify-center p-4 text-center">
              <Transition.Child
                as={Fragment}
                enter="ease-out duration-300"
                enterFrom="opacity-0 scale-95"
                enterTo="opacity-100 scale-100"
                leave="ease-in duration-200"
                leaveFrom="opacity-100 scale-100"
                leaveTo="opacity-0 scale-95"
              >
                <Dialog.Panel className="w-full max-w-md transform overflow-hidden rounded-2xl bg-ctp-surface0 p-6 text-left align-middle shadow-xl transition-all text-ctp-text">
                  <Dialog.Title
                    as="h3"
                    className="text-lg font-medium leading-6"
                  >
                    Add breakpoint
                  </Dialog.Title>
                  <div className="mt-2">
                    <p className="text-sm text-ctp-subtext0">
                      Submit a symbol name, address, etc.
                    </p>
                    <form>
                      <div>
                        <input 
                          type="text" 
                          id="breakpointLocation" 
                          placeholder="Breakpoint location" 
                          className="focus:ring-ctp-mauve bg-ctp-surface0 border-ctp-surface1 appearance-none rounded-lg border-2 px-4 py-3 placeholder:text-gray-500 focus:shadow-lg focus:outline-none focus:ring-2" 
                          required />
                      </div>
                    </form>
                  </div>

                  <div className="mt-4">
                    <button
                      type="button"
                      className="inline-flex justify-center rounded-md border border-transparent bg-blue-100 px-4 py-2 text-sm font-medium text-blue-900 hover:bg-blue-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                      onClick={() => dispatch(setBreakpointDialogIsOpen(false))}
                    >
                      Got it, thanks!
                    </button>
                  </div>
                </Dialog.Panel>
              </Transition.Child>
            </div>
          </div>
        </Dialog>
      </Transition>
